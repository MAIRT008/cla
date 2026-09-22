import {createLocalService} from '../../core/local/index.mjs';
import {createWorkspaceAdapter} from './workspace.mjs';

export {createWorkspaceAdapter};

export function createSyntheticLocalService(options) {
  const adapter = options.adapter || createWorkspaceAdapter(options);
  return createLocalService({...options, adapter});
}
