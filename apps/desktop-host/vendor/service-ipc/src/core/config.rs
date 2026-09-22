//! 受管配置核对（新增）。用 serde_yaml_ng 解析成 Mapping，拒绝控制器、secret、外部 UI 与 provider 这类
//! 能改变控制面或从外部路径/地址取数据的字段，再抽出实际回读要比对的事实：模式、TUN、IPv6、规则、组与出口。

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::core::structure::ServiceError;

pub const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// 这些键会重开或改写内核控制面、引用外部路径/地址，受管配置一律不接受。
pub const FORBIDDEN_KEYS: [&str; 12] = [
    "external-controller",
    "external-controller-tls",
    "external-controller-unix",
    "external-controller-pipe",
    "external-controller-cors",
    "secret",
    "external-ui",
    "external-ui-name",
    "external-ui-url",
    "external-doh-server",
    "rule-providers",
    "proxy-providers",
];

pub const CLAUDE_GROUP: &str = "CLAUDE-FIXED";
pub const EMERGENCY_GROUP: &str = "EMERGENCY-EGRESS";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleFact {
    pub rule_type: String,
    pub payload: String,
    pub proxy: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedFacts {
    pub mode: String,
    pub tun_enable: bool,
    pub ipv6: bool,
    pub rules: Vec<RuleFact>,
    pub group_names: Vec<String>,
    pub proxy_names: Vec<String>,
    pub claude_member: Option<String>,
    pub claude_processes: Vec<String>,
    pub emergency_processes: Vec<String>,
}

/// YAML 规则类型到 Mihomo `GET /rules` 返回的 `RuleType.String()`（constant/rule.go）。
pub fn rule_type_name(token: &str) -> String {
    let upper = token.trim().to_ascii_uppercase();
    let name = match upper.as_str() {
        "DOMAIN" => "Domain",
        "DOMAIN-SUFFIX" => "DomainSuffix",
        "DOMAIN-KEYWORD" => "DomainKeyword",
        "DOMAIN-REGEX" => "DomainRegex",
        "DOMAIN-WILDCARD" => "DomainWildcard",
        "GEOSITE" => "GeoSite",
        "GEOIP" => "GeoIP",
        "SRC-GEOIP" => "SrcGeoIP",
        "IP-ASN" => "IPASN",
        "SRC-IP-ASN" => "SrcIPASN",
        "IP-CIDR" | "IP-CIDR6" => "IPCIDR",
        "SRC-IP-CIDR" => "SrcIPCIDR",
        "IP-SUFFIX" => "IPSuffix",
        "SRC-IP-SUFFIX" => "SrcIPSuffix",
        "SRC-PORT" => "SrcPort",
        "DST-PORT" => "DstPort",
        "IN-PORT" => "InPort",
        "DSCP" => "DSCP",
        "IN-USER" => "InUser",
        "IN-NAME" => "InName",
        "IN-TYPE" => "InType",
        "PROCESS-NAME" => "ProcessName",
        "PROCESS-PATH" => "ProcessPath",
        "PROCESS-NAME-REGEX" => "ProcessNameRegex",
        "PROCESS-PATH-REGEX" => "ProcessPathRegex",
        "PROCESS-NAME-WILDCARD" => "ProcessNameWildcard",
        "PROCESS-PATH-WILDCARD" => "ProcessPathWildcard",
        "RULE-SET" => "RuleSet",
        "NETWORK" => "Network",
        "UID" => "Uid",
        "SUB-RULE" => "SubRules",
        "MATCH" => "Match",
        "AND" => "AND",
        "OR" => "OR",
        "NOT" => "NOT",
        _ => return token.trim().to_string(),
    };
    name.to_string()
}

/// 与 Mihomo 相同的切分：逻辑规则的载荷是首个逗号与最后一个逗号之间的整段括号，其余按逗号取类型/载荷/出口。
pub fn parse_rule_line(line: &str) -> Option<RuleFact> {
    let text = line.trim();
    let (head, rest) = text.split_once(',')?;
    let kind = head.trim().to_ascii_uppercase();
    if matches!(kind.as_str(), "AND" | "OR" | "NOT" | "SUB-RULE") {
        let (payload, proxy) = rest.rsplit_once(',')?;
        return Some(RuleFact { rule_type: rule_type_name(&kind), payload: payload.trim().to_string(), proxy: proxy.trim().to_string() });
    }
    if kind == "MATCH" {
        return Some(RuleFact { rule_type: "Match".to_string(), payload: String::new(), proxy: rest.trim().to_string() });
    }
    let mut parts = rest.split(',');
    let payload = parts.next()?.trim().to_string();
    let proxy = parts.next()?.trim().to_string();
    Some(RuleFact { rule_type: rule_type_name(&kind), payload, proxy })
}

/// 内核 `GET /rules` 对这条规则应当回报的载荷。普通规则就是 YAML 载荷；逻辑规则由 Mihomo `Logic.Payload()` 重新拼出
/// （rules/logic/logic.go，经 hub/route/rules.go 回报）：AND 为 `((类型,载荷) && (类型,载荷))`，OR 用 ` || `，
/// NOT 为 `(!(类型,载荷))`；子规则类型是 `RuleType.String()`，载荷不带 `no-resolve` 等参数。括号不配对时返回 None。
pub fn kernel_rule_payload(rule: &RuleFact) -> Option<String> {
    match rule.rule_type.as_str() {
        "AND" | "OR" | "NOT" => kernel_logic_payload(&rule.rule_type, &rule.payload),
        _ => Some(rule.payload.clone()),
    }
}

fn kernel_logic_payload(rule_type: &str, payload: &str) -> Option<String> {
    let rendered = logic_sub_rules(payload)?.iter().map(|sub| kernel_sub_rule(sub)).collect::<Option<Vec<String>>>()?;
    match rule_type {
        "AND" if !rendered.is_empty() => Some(format!("({})", rendered.join(" && "))),
        "OR" if !rendered.is_empty() => Some(format!("({})", rendered.join(" || "))),
        "NOT" if rendered.len() == 1 => Some(format!("(!{})", rendered[0])),
        _ => None,
    }
}

/// 与 Mihomo 相同的切分：载荷整体包在一对括号里，直接子括号各是一条子规则，更深的括号（例如路径里的 (x86)）属于子规则自己的载荷。
fn logic_sub_rules(payload: &str) -> Option<Vec<String>> {
    let text = payload.trim();
    if !text.starts_with('(') || !text.ends_with(')') {
        return None;
    }
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut subs = Vec::new();
    for (index, character) in text.char_indices() {
        match character {
            '(' => {
                depth += 1;
                if depth == 2 {
                    start = index + 1;
                }
            }
            ')' => {
                if depth == 0 {
                    return None;
                }
                if depth == 2 {
                    subs.push(text[start..index].to_string());
                }
                depth -= 1;
                if depth == 0 && index + 1 != text.len() {
                    return None;
                }
            }
            other if depth == 1 && other != ',' && !other.is_whitespace() => return None,
            _ => {}
        }
    }
    (depth == 0).then_some(subs)
}

fn kernel_sub_rule(sub: &str) -> Option<String> {
    let items: Vec<&str> = sub.split(',').map(str::trim).collect();
    let kind = items.first()?.to_ascii_uppercase();
    match kind.as_str() {
        "AND" | "OR" | "NOT" => Some(format!("({},{})", rule_type_name(&kind), kernel_logic_payload(&kind, &items[1..].join(","))?)),
        "MATCH" | "SUB-RULE" | "" => None,
        _ => Some(format!("({},{})", rule_type_name(&kind), items.get(1)?)),
    }
}

fn invalid(reason: impl Into<String>) -> ServiceError {
    ServiceError::new("CONFIG_INVALID", reason)
}

fn names(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|item| item.get("name").and_then(Value::as_str)).map(str::to_string).collect())
        .unwrap_or_default()
}

fn process_in_logic_payload(payload: &str) -> Option<String> {
    let marker = "PROCESS-NAME,";
    let start = payload.to_ascii_uppercase().find(marker)? + marker.len();
    let tail = &payload[start..];
    let end = tail.find(')').unwrap_or(tail.len());
    Some(tail[..end].trim().to_string())
}

pub fn inspect_managed_yaml(text: &str) -> Result<ManagedFacts, ServiceError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(invalid("受管配置超过大小上限"));
    }
    let root: Value = serde_yaml_ng::from_str(text).map_err(|_| invalid("受管配置不是可解析的 YAML"))?;
    let mapping = root.as_object().ok_or_else(|| invalid("受管配置顶层必须是 Mapping"))?;
    if let Some(key) = FORBIDDEN_KEYS.iter().find(|key| mapping.contains_key(**key)) {
        return Err(ServiceError::new("CONFIG_FIELD_FORBIDDEN", format!("受管配置不能包含 {key}")));
    }
    let raw_rules = mapping.get("rules").and_then(Value::as_array).ok_or_else(|| invalid("受管配置必须有 rules 列表"))?;
    let mut rules = Vec::with_capacity(raw_rules.len());
    for item in raw_rules {
        let line = item.as_str().ok_or_else(|| invalid("规则必须是文本"))?;
        rules.push(parse_rule_line(line).ok_or_else(|| invalid("有规则无法解析出类型、载荷与出口"))?);
    }
    if rules.last().map(|rule| rule.rule_type.as_str()) != Some("Match") {
        return Err(invalid("最后一条规则必须是 MATCH"));
    }
    let groups = mapping.get("proxy-groups").and_then(Value::as_array).cloned().unwrap_or_default();
    let group_names = names(mapping.get("proxy-groups"));
    let claude_member = groups
        .iter()
        .find(|group| group.get("name").and_then(Value::as_str) == Some(CLAUDE_GROUP))
        .and_then(|group| group.get("proxies").and_then(Value::as_array).and_then(|list| list.first()).and_then(Value::as_str))
        .map(str::to_string);
    let claude_processes = rules
        .iter()
        .filter(|rule| rule.rule_type == "ProcessName" && rule.proxy == CLAUDE_GROUP)
        .map(|rule| rule.payload.clone())
        .collect();
    let mut emergency_processes: Vec<String> = rules
        .iter()
        .filter(|rule| rule.rule_type == "AND" && rule.proxy != CLAUDE_GROUP)
        .filter_map(|rule| process_in_logic_payload(&rule.payload))
        .collect();
    emergency_processes.sort();
    emergency_processes.dedup();
    let tun_enable = mapping.get("tun").and_then(|tun| tun.get("enable")).and_then(Value::as_bool).unwrap_or(false);
    Ok(ManagedFacts {
        mode: mapping.get("mode").and_then(Value::as_str).unwrap_or("rule").to_ascii_lowercase(),
        tun_enable,
        ipv6: mapping.get("ipv6").and_then(Value::as_bool).unwrap_or(true),
        rules,
        group_names,
        proxy_names: names(mapping.get("proxies")),
        claude_member,
        claude_processes,
        emergency_processes,
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReadbackCheck {
    pub name: String,
    pub ok: bool,
    pub expected: Value,
    pub actual: Value,
}

fn check(name: &str, ok: bool, expected: Value, actual: Value) -> ReadbackCheck {
    ReadbackCheck { name: name.to_string(), ok, expected, actual }
}

pub fn normalize_version(version: &str) -> String {
    version.trim().trim_start_matches('v').to_string()
}

/// 实际回读与受管事实逐项比较。`version/general/rules/proxies` 都是内核接口的原始返回；
/// 读取失败的一项以 `Value::Null` 传入并判为不通过，不拿期望值补。
pub fn compare_readback(
    facts: &ManagedFacts,
    kernel_version: &Value,
    general: &Value,
    rules: &Value,
    proxies: &Value,
) -> Vec<ReadbackCheck> {
    let mut checks = Vec::new();
    let version = kernel_version.as_str().map(normalize_version);
    checks.push(check(
        "kernel_version",
        version.as_deref() == Some(normalize_version(crate::core::paths::KERNEL_VERSION).as_str()),
        Value::String(crate::core::paths::KERNEL_VERSION.to_string()),
        kernel_version.clone(),
    ));
    let mode = general.get("mode").and_then(Value::as_str).map(str::to_ascii_lowercase);
    checks.push(check("mode", mode.as_deref() == Some(facts.mode.as_str()), Value::String(facts.mode.clone()), general.get("mode").cloned().unwrap_or(Value::Null)));
    let tun = general.get("tun").and_then(|tun| tun.get("enable")).and_then(Value::as_bool);
    checks.push(check("tun", tun == Some(facts.tun_enable), Value::Bool(facts.tun_enable), tun.map(Value::Bool).unwrap_or(Value::Null)));
    let ipv6 = general.get("ipv6").and_then(Value::as_bool);
    checks.push(check("ipv6", ipv6 == Some(facts.ipv6), Value::Bool(facts.ipv6), ipv6.map(Value::Bool).unwrap_or(Value::Null)));

    let actual_rules: Option<Vec<RuleFact>> = rules.get("rules").and_then(Value::as_array).map(|items| {
        items
            .iter()
            .map(|item| RuleFact {
                rule_type: item.get("type").and_then(Value::as_str).unwrap_or_default().to_string(),
                payload: item.get("payload").and_then(Value::as_str).unwrap_or_default().to_string(),
                proxy: item.get("proxy").and_then(Value::as_str).unwrap_or_default().to_string(),
            })
            .collect()
    });
    let rules_match = actual_rules.as_ref().map(|actual| {
        actual.len() == facts.rules.len()
            && actual.iter().zip(facts.rules.iter()).all(|(left, right)| {
                left.rule_type == right.rule_type
                    && kernel_rule_payload(right).map(|expected| left.payload.eq_ignore_ascii_case(&expected)).unwrap_or(false)
                    && left.proxy == right.proxy
            })
    });
    checks.push(check(
        "rules",
        rules_match == Some(true),
        serde_json::json!({"count": facts.rules.len()}),
        serde_json::json!({"count": actual_rules.as_ref().map(Vec::len)}),
    ));

    let table = proxies.get("proxies").and_then(Value::as_object);
    let missing: Vec<String> = facts
        .group_names
        .iter()
        .chain(facts.proxy_names.iter())
        .filter(|name| table.map(|map| !map.contains_key(name.as_str())).unwrap_or(true))
        .cloned()
        .collect();
    checks.push(check("outbounds", table.is_some() && missing.is_empty(), serde_json::json!({"missing": []}), serde_json::json!({"missing": missing})));
    if let Some(expected) = &facts.claude_member {
        let now = table.and_then(|map| map.get(CLAUDE_GROUP)).and_then(|group| group.get("now")).and_then(Value::as_str);
        checks.push(check("claude_member", now == Some(expected.as_str()), Value::String(expected.clone()), now.map(|value| Value::String(value.to_string())).unwrap_or(Value::Null)));
    }
    checks
}

#[cfg(test)]
pub(crate) const SAMPLE_MANAGED_YAML: &str = r#"mode: rule
ipv6: true
tun:
  enable: true
  stack: system
proxies:
  - name: EXIT-A
    type: socks5
    server: 192.0.2.10
    port: 1080
    username: synthetic-user
    password: synthetic-pass
proxy-groups:
  - name: PROXY-A
    type: select
    proxies: [EXIT-A]
  - name: CLAUDE-FIXED
    type: select
    proxies: [PROXY-A]
  - name: GENERAL-EGRESS
    type: select
    proxies: [PROXY-A]
  - name: EMERGENCY-EGRESS
    type: select
    proxies: [PROXY-A]
rules:
  - AND,((PROCESS-PATH,C:\Program Files\Claude\claude.exe),(IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,43123),(NETWORK,tcp)),DIRECT
  - NETWORK,udp,REJECT
  - PROCESS-NAME,claude.exe,CLAUDE-FIXED
  - DOMAIN-SUFFIX,claude.ai,CLAUDE-FIXED
  - AND,((PROCESS-NAME,firefox.exe),(DOMAIN-SUFFIX,claude.ai)),CLAUDE-FIXED
  - AND,((PROCESS-NAME,firefox.exe),(DOMAIN-SUFFIX,support.example)),EMERGENCY-EGRESS
  - MATCH,GENERAL-EGRESS
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;


    #[test]
    fn managed_facts_come_from_the_parsed_mapping() {
        let facts = inspect_managed_yaml(SAMPLE_MANAGED_YAML).unwrap();
        assert_eq!(facts.mode, "rule");
        assert!(facts.tun_enable && facts.ipv6);
        assert_eq!(facts.rules.len(), 7);
        assert_eq!(facts.rules[4], RuleFact { rule_type: "AND".into(), payload: "((PROCESS-NAME,firefox.exe),(DOMAIN-SUFFIX,claude.ai))".into(), proxy: "CLAUDE-FIXED".into() });
        assert_eq!(facts.claude_member.as_deref(), Some("PROXY-A"));
        assert_eq!(facts.claude_processes, vec!["claude.exe".to_string()]);
        assert_eq!(facts.emergency_processes, vec!["firefox.exe".to_string()]);
        assert_eq!(facts.proxy_names, vec!["EXIT-A".to_string()]);
    }

    #[test]
    fn control_plane_and_provider_fields_are_rejected() {
        for key in FORBIDDEN_KEYS {
            let text = format!("{key}: x\n{SAMPLE_MANAGED_YAML}");
            assert_eq!(inspect_managed_yaml(&text).unwrap_err().code, "CONFIG_FIELD_FORBIDDEN", "{key}");
        }
        assert_eq!(inspect_managed_yaml("- not\n- a mapping\n").unwrap_err().code, "CONFIG_INVALID");
        assert_eq!(inspect_managed_yaml("rules: ['DOMAIN,a.example,DIRECT']").unwrap_err().code, "CONFIG_INVALID", "没有 MATCH 兜底");
    }

    #[test]
    fn readback_compares_actual_kernel_answers_not_expected_values() {
        let facts = inspect_managed_yaml(SAMPLE_MANAGED_YAML).unwrap();
        let rules: Vec<Value> = facts
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| json!({"index": index, "type": rule.rule_type, "payload": kernel_rule_payload(rule).unwrap(), "proxy": rule.proxy, "size": -1}))
            .collect();
        let mut proxies = serde_json::Map::new();
        for name in facts.group_names.iter().chain(facts.proxy_names.iter()) {
            proxies.insert(name.clone(), json!({"name": name, "now": "PROXY-A"}));
        }
        let general = json!({"mode": "rule", "tun": {"enable": true}, "ipv6": true});
        let good = compare_readback(&facts, &json!("v1.19.30"), &general, &json!({"rules": rules}), &json!({"proxies": proxies}));
        assert!(good.iter().all(|item| item.ok), "{good:?}");

        let lost_tun = compare_readback(&facts, &json!("v1.19.30"), &json!({"mode": "rule", "tun": {"enable": false}, "ipv6": true}), &json!({"rules": rules}), &json!({"proxies": proxies}));
        assert!(lost_tun.iter().any(|item| item.name == "tun" && !item.ok));
        let old_rules = compare_readback(&facts, &json!("v1.19.30"), &general, &json!({"rules": rules[..3].to_vec()}), &json!({"proxies": proxies}));
        assert!(old_rules.iter().any(|item| item.name == "rules" && !item.ok));
        let unread = compare_readback(&facts, &Value::Null, &Value::Null, &Value::Null, &Value::Null);
        assert!(unread.iter().all(|item| !item.ok), "读不到的一项不能用期望值补成通过");
        let other_kernel = compare_readback(&facts, &json!("v1.19.31"), &general, &json!({"rules": rules}), &json!({"proxies": proxies}));
        assert!(other_kernel.iter().any(|item| item.name == "kernel_version" && !item.ok));
        let yaml_echo: Vec<Value> = facts.rules.iter().enumerate().map(|(index, rule)| json!({"index": index, "type": rule.rule_type, "payload": rule.payload, "proxy": rule.proxy, "size": -1})).collect();
        let echoed = compare_readback(&facts, &json!("v1.19.30"), &general, &json!({"rules": yaml_echo}), &json!({"proxies": proxies}));
        assert!(echoed.iter().any(|item| item.name == "rules" && !item.ok), "内核不会照 YAML 原文回报逻辑规则，原文回显不算一致");
    }

    #[test]
    fn logic_rules_are_compared_in_the_form_the_kernel_reports() {
        let facts = inspect_managed_yaml(SAMPLE_MANAGED_YAML).unwrap();
        assert_eq!(facts.rules[0], RuleFact { rule_type: "AND".into(), payload: r"((PROCESS-PATH,C:\Program Files\Claude\claude.exe),(IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,43123),(NETWORK,tcp))".into(), proxy: "DIRECT".into() });
        assert_eq!(facts.emergency_processes, vec!["firefox.exe".to_string()], "精确回环规则不是应急浏览器规则");
        assert_eq!(
            kernel_rule_payload(&facts.rules[0]).as_deref(),
            Some(r"((ProcessPath,C:\Program Files\Claude\claude.exe) && (IPCIDR,127.0.0.1/32) && (DstPort,43123) && (Network,tcp))"),
            "Logic.Payload()：子规则类型用 RuleType.String()，参数不回报"
        );
        assert_eq!(kernel_rule_payload(&facts.rules[4]).as_deref(), Some("((ProcessName,firefox.exe) && (DomainSuffix,claude.ai))"));
        assert_eq!(kernel_rule_payload(&facts.rules[1]).as_deref(), Some("udp"), "普通规则照原载荷");
        let not_rule = RuleFact { rule_type: "NOT".into(), payload: "((DOMAIN,a.example))".into(), proxy: "REJECT".into() };
        assert_eq!(kernel_rule_payload(&not_rule).as_deref(), Some("(!(Domain,a.example))"));
        let nested = RuleFact { rule_type: "AND".into(), payload: r"((PROCESS-PATH,C:\Program Files (x86)\App\app.exe),(OR,((DST-PORT,1),(DST-PORT,2))))".into(), proxy: "DIRECT".into() };
        assert_eq!(kernel_rule_payload(&nested).as_deref(), Some(r"((ProcessPath,C:\Program Files (x86)\App\app.exe) && (OR,((DstPort,1) || (DstPort,2))))"), "路径里的括号属于子规则载荷");
        for broken in ["((DOMAIN,a.example)", "(DOMAIN,a.example),(DOMAIN,b.example)", "(x,(DOMAIN,a.example))", "((MATCH,x))"] {
            let rule = RuleFact { rule_type: "AND".into(), payload: broken.into(), proxy: "DIRECT".into() };
            assert_eq!(kernel_rule_payload(&rule), None, "{broken}");
        }
    }
}
