import type { SastRule } from '../types.js';
import { RULE_SEC_SAST_EVAL } from './eval.js';
import { RULE_SEC_SAST_REACT_DANGEROUS_HTML } from './react-danger.js';
import { RULE_SEC_SAST_COMMAND_INJECTION } from './exec.js';
import { RULE_SEC_SAST_SQL_INJECTION } from './sql.js';
import { RULE_SEC_SAST_INNERHTML } from './dom-xss.js';
import { RULE_SEC_SAST_INSECURE_HTTP } from './insecure-http.js';
import { RULE_SEC_SAST_WEAK_CRYPTO } from './crypto.js';

export { RULE_SEC_SAST_EVAL } from './eval.js';
export { RULE_SEC_SAST_REACT_DANGEROUS_HTML } from './react-danger.js';
export { RULE_SEC_SAST_COMMAND_INJECTION } from './exec.js';
export { RULE_SEC_SAST_SQL_INJECTION } from './sql.js';
export { RULE_SEC_SAST_INNERHTML } from './dom-xss.js';
export { RULE_SEC_SAST_INSECURE_HTTP } from './insecure-http.js';
export { RULE_SEC_SAST_WEAK_CRYPTO } from './crypto.js';

export const BUILT_IN_SAST_RULES: SastRule[] = [
  RULE_SEC_SAST_EVAL,
  RULE_SEC_SAST_REACT_DANGEROUS_HTML,
  RULE_SEC_SAST_COMMAND_INJECTION,
  RULE_SEC_SAST_SQL_INJECTION,
  RULE_SEC_SAST_INNERHTML,
  RULE_SEC_SAST_INSECURE_HTTP,
  RULE_SEC_SAST_WEAK_CRYPTO
];
