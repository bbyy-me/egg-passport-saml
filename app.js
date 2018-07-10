'use strict';

const Strategy = require('passport-saml').Strategy;
const utils = require('./utils');

module.exports = async app => {
  const config = app.config.passportSaml;

  const res = await app.curl(config.idpMetadataUrl);
  const idpMetadata = await utils.parserMetadata(res.data.toString());

  const configForStrategy = {
    passReqToCallback: true,
    entryPoint: idpMetadata.sso.redirectUrl,

    issuer: config.issuer,
    logoutUrl: idpMetadata.slo.redirectUrl,
    logoutCallbackUrl: '/passport/saml/logout',

    cert: idpMetadata.signingKeys[0],
    signatureAlgorithm: 'sha256',
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

  strategy.getMetadata = () => {
    const metadataParams = {};
    return utils.getMetadata({
      host,
      cert: config.cert,
    });
  };
  // passport.authenticate('saml')(ctx);
  // passportSaml.getMetadata
  // passportSaml.getLogoutUrl
  // passportSaml._saml.validatePostRequest

  const controllers = {
    metadata: {
      method: 'get',
      path: '/passport/saml/metadata',
      controller: async (ctx) => {
        const metadataParams = {
          host,
          cert: config.cert,
        };
        ctx.set('Content-Type', 'application/xml');
        ctx.body = utils.getMetadata(metadataParams);
      },
    },
    sso: {
      method: 'get',
      path: '/passport/saml/metadata',
      controller: async (ctx) => {
        await app.passport.authenticate('saml')(ctx);
      },
    },
    ssoCallback: {
      method: 'get',
      path: '/passport/saml/metadata',
      controller: async (ctx) => {
        await app.passport.authenticate('saml')(ctx);
        const session = ctx.helper.getSymbolValue(ctx, 'context#_contextSession');
        if (!session) { return; }
        ctx.user.SPClientId = session.externalKey;
        ctx.model.Session.create({
          sp_client_id: ctx.user.SPClientId,
          idp_client_id: ctx.user.IDPClientId,
          user_id: ctx.user.email,
        });
      },
    },
    logout: {
      method: 'get',
      path: '/passport/saml/metadata',
      controller: async (ctx) => {
        if (!ctx.req.user) {
          ctx.redirect('/');
          return;
        }
        ctx.req.user.sessionIndex = ctx.req.user.IDPClientId;
        const idpLogoutUrl = await strategy.getLogoutUrl(ctx.req);
        await app.curl(idpLogoutUrl);
        ctx.logout();
        ctx.redirect('/');
      },
    },
    slo: {
      method: 'get',
      path: '/passport/saml/metadata',
      controller: async (ctx) => {
        console.log(99999, ctx.request.body);
        strategy._saml.validatePostRequest(ctx.request.body, function() {
          console.log(222, arguments);
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
  config.routers.forEach(r => {
    app.router[r.method](r.path, r.controller);
  });
};
