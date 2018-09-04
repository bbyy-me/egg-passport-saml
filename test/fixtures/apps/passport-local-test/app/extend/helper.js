'use strict';
module.exports = {
  getSymbolValue(obj, symbolKey) {
    if (!obj) {
      return;
    }
    if (!symbolKey) {
      return;
    }
    const s = Object.getOwnPropertySymbols(obj).find(symbol => symbol.toString() === `Symbol(${symbolKey})`);
    return obj[s];
  },

  randomCode() {
    return Math.random() * 900000 | 100000; // eslint-disable-line
  },
};
