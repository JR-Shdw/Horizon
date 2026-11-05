"""The Clear Token button must leave no copy in storage or in any tab."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

API_JS = Path(__file__).resolve().parents[1] / "frontend/js/api.js"
TOKEN = "rh_" + "a" * 40

HARNESS = """
const vm = require('vm');
const fs = require('fs');
const store = new Map([['rh_token', process.argv[1]], ['sidebar-mode', 'expanded']]);
const listeners = {};
const input = { value: process.argv[1] };
const context = {
  console,
  localStorage: {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, v),
    removeItem: (k) => store.delete(k),
  },
  document: { getElementById: () => input },
};
context.window = {
  addEventListener: (name, fn) => { listeners[name] = fn; },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
const token = () => vm.runInContext('getToken()', context);
const out = { loaded: token() };
vm.runInContext('clearToken()', context);
out.afterClear = token();
out.stored = store.has('rh_token');
out.sidebarKept = store.has('sidebar-mode');
vm.runInContext(`setToken(${JSON.stringify(process.argv[1])})`, context);
listeners.storage({ key: 'sidebar-mode', newValue: 'x' });
out.afterOtherKey = token();
listeners.storage({ key: 'rh_token', newValue: null });
out.afterOtherTabClear = token();
out.input = input.value;
vm.runInContext(`setToken(${JSON.stringify(process.argv[1])})`, context);
listeners.storage({ key: null, newValue: null });
out.afterStorageClear = token();
console.log(JSON.stringify(out));
"""


@pytest.mark.skipif(not shutil.which("node"), reason="node is required")
def test_clear_token_reaches_storage_and_other_tabs():
    result = subprocess.run(
        ["node", "-e", HARNESS, TOKEN, str(API_JS)],
        capture_output=True,
        text=True,
        check=True,
    )
    state = json.loads(result.stdout)
    assert state["loaded"] == TOKEN
    assert state["afterClear"] == ""
    assert state["stored"] is False
    assert state["sidebarKept"] is True
    assert state["afterOtherKey"] == TOKEN
    assert state["afterOtherTabClear"] == ""
    assert state["input"] == ""
    assert state["afterStorageClear"] == ""


def test_api_js_listens_for_token_changes_from_other_tabs():
    assert "addEventListener('storage'" in API_JS.read_text()
