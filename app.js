'use strict';

const { xpath } = require('xml-crypto');
const xmldom = require('xmldom');
const Strategy = require('passport-saml').Strategy;
const utils = require('./utils');
const SPIDPRE = 'spid';

module.exports = async app => {
  const config = app.config.passportSaml;

  const res = await app.curl(config.idpMetadataUrl);
  const idpMetadata = await utils.parserMetadata(res.data.toString());

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

  // passport.authenticate('saml')(ctx);
  // passportSaml.getMetadata
  // passportSaml.getLogoutUrl
  // passportSaml._saml.validatePostRequest

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
        const xml = new Buffer(ctx.request.body.SAMLResponse, 'base64').toString('utf8');
        const doc = new xmldom.DOMParser({}).parseFromString(xml);
        if (!doc.hasOwnProperty('documentElement')) {
          throw new Error('SAMLResponse is not valid base64-encoded XML');
        }
        const inResponseTo = xpath(doc, "/*[local-name()='Response']/@InResponseTo");
        if (!inResponseTo || !inResponseTo.length) { return; }
        const spid = `${SPIDPRE}${inResponseTo[0].nodeValue}`;
        ctx.user.spid = spid;
        await app.sessionStore.set(spid, session.externalKey);
      },
    },
    logout: {
      method: 'get',
      path: '/passport/saml/logout',
      controller: async (ctx) => {
        if (ctx.user) {
          const spid = ctx.user.spid;
          ctx.req.user.sessionIndex = spid.slice(SPIDPRE.length);
          const idpLogoutUrl = await strategy.getLogoutUrl(ctx);
          await app.curl(idpLogoutUrl);
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
          const sessionId = await app.sessionStore.get(`${SPIDPRE}${res.sessionIndex}`);
          await app.sessionStore.destroy(sessionId);
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
