'use strict';
// const cacheProvider = {
//   save(key,value,callback) {
//     // save the key with the optional value, invokes the callback with the value saves
//   },
//   get(key,callbck) {
//      // invokes 'callback' and passes the value if found, null otherwise
//   },
//   remove(key, callback) {
//     // removes the key from the cache, invokes `callback` with the
//     // key removed, null if no key is removed
//   }
// }
exports.keys = '123456';
exports.cluster = {
  listen: {
    port: 3001,
  },
};
exports.passportSaml = {
  idpMetadataUrl: 'http://127.0.0.1:5700/sso/saml2.0/metadata',
  issuer: 'http://localhost:3001',
  // cacheProvider:cacheProvider,
};
exports.redis = {
  client: {
    port: 6379,
    host: '127.0.0.1',
    password: '',
    db: 0,
  },
};
exports.security = {
  csrf: false,
};
