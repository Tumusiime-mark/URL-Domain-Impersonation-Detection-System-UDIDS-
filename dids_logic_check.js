const fs = require("fs");
const vm = require("vm");

const html = fs.readFileSync("index.html", "utf8");
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)][0][1];

function element() {
  return {
    value: "",
    textContent: "",
    innerHTML: "",
    dataset: {},
    style: {},
    classList: {
      add() {},
      remove() {},
      contains() {
        return false;
      },
    },
    addEventListener() {},
    querySelectorAll() {
      return [];
    },
  };
}

const elements = new Map();
const context = {
  console,
  localStorage: {
    getItem() {
      return null;
    },
    setItem() {},
  },
  document: {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    querySelectorAll() {
      return [];
    },
    createElement() {
      return element();
    },
    body: {
      appendChild() {},
    },
  },
  Blob: class Blob {
    constructor(parts, options) {
      this.parts = parts;
      this.options = options;
    }
  },
  URL: {
    createObjectURL() {
      return "blob:test";
    },
    revokeObjectURL() {},
  },
  confirm() {
    return true;
  },
  clearTimeout() {},
  setTimeout() {
    return 1;
  },
  setInterval() {
    return 1;
  },
};

vm.createContext(context);
vm.runInContext(
  `${script}
  const base = "mak.ac.ug";
  globalThis.__results = [
    ["https://mak.ac.ug/", analyze(base, "https://mak.ac.ug/")],
    ["https://webmail.mak.ac.ug/", analyze(base, "https://webmail.mak.ac.ug/")],
    ["https://mak-ac-ug-login.com/", analyze(base, "https://mak-ac-ug-login.com/")],
    ["https://mak.ac-ug.com/", analyze(base, "https://mak.ac-ug.com/")],
    ["https://mаk.ac.ug/", analyze(base, "https://mаk.ac.ug/")],
    ["https://makacug.online/", analyze(base, "https://makacug.online/")]
  ].map(([url, result]) => ({
    url,
    risk: result.risk,
    severity: result.severity,
    decision: result.decision,
    type: result.attackType,
    reasons: result.reasons
  }));
  `,
  context
);

console.log(JSON.stringify(context.__results, null, 2));
