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
    logoutCallbackUrl: `${config.issuer}/passport/saml/logout`,

    callbackUrl: `${config.issuer}/passport/saml`,

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
  strategy.getSPMetadata = () => {
    return app.passportSaml.generateServiceProviderMetadata(config.cert);
  };

  // strategy.getMetadata = () => {
  //   const metadataParams = {};
  //   return utils.getMetadata({
  //     host,
  //     cert: config.cert,
  //   });
  // };
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
        ctx.user.SPClientId = session.externalKey;
        strategy.modelSession.create({
          SPClientId: ctx.user.SPClientId,
          IDPClientId: ctx.user.IDPClientId,
          userId: ctx.user.nameID,
        });
      },
    },
    logout: {
      method: 'get',
      path: '/passport/saml/logout',
      controller: async (ctx) => {
        if (ctx.req.user) {
          ctx.req.user.sessionIndex = ctx.req.user.IDPClientId;
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
          const sessionInMongo = await strategy.modelSession.get({ IDPClientId: res.sessionIndex, userId: res.nameID });
          if (!sessionInMongo) return;
          const sessionInRedis = await app.sessionStore.get(sessionInMongo.sp_client_id);
          sessionInRedis.passport = {};
          await app.sessionStore.set(sessionInMongo.sp_client_id, sessionInRedis);
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
  if (!app.model.Session) {
    console.error('需要定义session表');
    return;
  }
  strategy.modelSession = {
    async create({ SPClientId, IDPClientId, userId }) {
      const session = await app.model.Session.findOne({
        sp_client_id: SPClientId,
        idp_client_id: IDPClientId,
        user_id: userId,
      });
      if (!session) {
        await app.model.Session.create({
          sp_client_id: SPClientId,
          idp_client_id: IDPClientId,
          user_id: userId,
        });
      }
    },
    async get({ SPClientId, IDPClientId, userId }) {
      const query = {};
      if (SPClientId) query.sp_client_id = SPClientId;
      if (IDPClientId) query.idp_client_id = IDPClientId;
      if (userId) query.user_id = userId;
      return app.model.Session.findOne(query);
    },
    async delete({ SPClientId, IDPClientId, userId }) {
      const query = {};
      if (SPClientId) query.sp_client_id = SPClientId;
      if (IDPClientId) query.idp_client_id = IDPClientId;
      if (userId) query.user_id = userId;
      await app.model.Session.deleteMany(query);
      // 删除Redis中的session
    },
  };
  config.routers.forEach(router => {
    if (!router) return;

    const ctrl = controllers[router.controller];
    if (!ctrl) return;

    app.router[ctrl.method](router.path || ctrl.path, ctrl.controller);
  });
};
