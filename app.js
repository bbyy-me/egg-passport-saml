'use strict';

const Strategy = require('passport-saml').Strategy;
const utils = require('./utils');
const routersCreater = require('./routers');

module.exports = async app => {
  const config = app.config.passportSaml;
  if (!config.enable) return;

  const { idpMetadataUrl } = config;

  const res = await app.curl(idpMetadataUrl);
  const idpMetadata = await utils.parserMetadata(res.data.toString());

  if (!app.sessionStore) {
    console.warn('Warning: we suggest you to deploy sessionStore with plugin such as egg-session-redis');
  }

  const cacheProvider = {
    async save(key, value, callback) {
      const cacheKey = `${app.name}_saml_${key}`;
      if (!app.sessionStore) {
        console.log('Warning: we suggest you to deploy sessionStore with plugin such as egg-session-redis');
      }
      if (!await app.sessionStore.get(cacheKey)) {
        try {
          await app.sessionStore.set(cacheKey, value);
        } catch (err) {
          callback(err);
        }
        callback(null, value);
      } else {
        callback(null, null);
      }
    },
    async get(key, callback) {
      if (!app.sessionStore) {
        console.log('Warning: we suggest you to deploy sessionStore with plugin such as egg-session-redis');
      }
      // invokes 'callback' and passes the value if found, null otherwise
      let cacheValue;
      const cacheKey = `${app.name}_saml_${key}`;
      try {
        cacheValue = await app.sessionStore.get(cacheKey);
        // console.log('get cacheValue:',cacheKey,cacheValue)
      } catch (err) {
        callback(err);
      }
      if (!cacheValue) {
        callback(null, null);
      } else {
        callback(null, cacheValue);
      }
    },
    async remove(key, callback) {
      // removes the key from the cache, invokes `callback` with the
      // key removed, null if no key is removed
      let cacheValue;
      const cacheKey = `${app.name}_saml_${key}`;
      try {
        cacheValue = await app.sessionStore.get(cacheKey);
        // console.log('destroy cacheValue:',cacheKey,cacheValue)
      } catch (err) {
        callback(err);
      }
      if (!cacheValue) {
        callback(null, null);
      } else {
        try {
          await app.sessionStore.destroy(cacheKey);
        } catch (err) {
          callback(err);
        }
        callback(null, key);
      }
    },
  };

  const configForStrategy = {
    passReqToCallback: true,
    entryPoint: idpMetadata.sso.redirectUrl,

    issuer: config.issuer,
    logoutUrl: idpMetadata.slo.redirectUrl,
    logoutCallbackUrl: `${config.issuer}/passport/saml/logout`,

    callbackUrl: `${config.issuer}/passport/saml`,

    cert: idpMetadata.signingKeys[0],
    signatureAlgorithm: 'sha256',
    validateInResponseTo: true,
    cacheProvider: config.cacheProvider || cacheProvider,
    privateCert: config.key,
    decryptionPvk: config.key,

    acceptedClockSkewMs: config.acceptedClockSkewMs,
  };

  const strategy = new Strategy(configForStrategy, (req, user, done) => {
    app.passport.doVerify(req, user, done);
  });

  strategy.getLogoutUrl = async ctx => {
    const req = ctx.req;
    return new Promise((reslove, reject) => {
      strategy.logout(req, (err, url) => {
        err ? reject(err) : reslove(url);
      });
    });
  };
  strategy.getSPMetadata = () => {
    return app.passportSaml.generateServiceProviderMetadata(config.cert);
  };


  app.passportSaml = strategy;
  app.passport.use(strategy);

  if (!config.mountRouter) return;
  routersCreater(app);
};
