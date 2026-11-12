// Shared module exporting both tainted and constant values.
export const query = location.search;
export const FIXED_TITLE = "Welcome";
export function readParam(name) {
  const params = new URLSearchParams(location.search);
  return params.get(name);
}
