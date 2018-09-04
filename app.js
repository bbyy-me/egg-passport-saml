'use strict';

const Strategy = require('passport-saml').Strategy;
const utils = require('./utils');

module.exports = async app => {
  const config = app.config.passportSaml;

  const res = await app.curl(config.idpMetadataUrl);
  const idpMetadata = await utils.parserMetadata(res.data.toString());

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

  const controllers = {
    metadata: {
      method: 'get',
      path: '/passport/saml/metadata',
      controller: async (ctx) => {
        ctx.set('Content-Type', 'application/xml');
        ctx.body = app.passportSaml.getSPMetadata();
      },
    },
    sso: {
      method: 'get',
      path: '/passport/saml',
      controller: async (ctx) => {
        await app.passport.authenticate('saml')(ctx);
      },
    },
    ssoCallback: {
      method: 'post',
      path: '/passport/saml',
      controller: async (ctx) => {
        await app.passport.authenticate('saml')(ctx);
        const session = ctx.helper.getSymbolValue(ctx, 'context#_contextSession');
        if (!session) { return; }
        const spid = `idp_${ctx.user.IDPClientId}_${ctx.user.nameID}`;
        await app.sessionStore.set(spid, session.externalKey);
      },
    },
    logout: {
      method: 'get',
      path: '/passport/saml/logout',
      controller: async (ctx) => {
        if (ctx.user) {
          ctx.req.user.sessionIndex = ctx.user.IDPClientId;
          const idpLogoutUrl = await strategy.getLogoutUrl(ctx);
          await app.curl(idpLogoutUrl);
          const idpId = `idp_${ctx.user.IDPClientId}_${ctx.user.nameID}`;
          await app.sessionStore.destroy(idpId);
        }
        ctx.logout();
        ctx.redirect('/');
      },
    },
    slo: {
      method: 'post',
      path: '/passport/saml/logout',
      controller: async (ctx) => {
        strategy._saml.validatePostRequest(ctx.request.body, async function(err, res) {
          if (err) return;
          const idpId = `idp_${res.sessionIndex}_${res.nameID}`;
          const sessionId = await app.sessionStore.get(idpId);
          const session = await app.sessionStore.get(sessionId);
          if (session && session.passport && session.passport.user) {
            if (session._expire) {
              session._expire - new Date().getTime();
            }
            session.passport.user = null;
            await app.sessionStore.set(sessionId, session, session._expire ? session._expire - new Date().getTime() : undefined);
          }

          await app.sessionStore.destroy(idpId);
        });
        ctx.body = 'OK';
      },
    },
  };

  app.passportSaml = strategy;
  app.passport.use(strategy);

  if (!config.mountRouter || !Array.isArray(config.routers)) {
    return;
  }

  config.routers.forEach(router => {
    if (!router) return;

    const ctrl = controllers[router.controller];
    if (!ctrl) return;

    app.router[ctrl.method](router.path || ctrl.path, ctrl.controller);
  });
};
