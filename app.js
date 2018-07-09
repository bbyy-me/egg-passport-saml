'use strict';

const Strategy = require('passport-saml').Strategy;
const parser = require('./metadata_parser');
const utils = require('./utils');

module.exports = async (app) => {
  const config = app.config.passportSaml;
  const spCert = await app.model.Setting.findOne({
    where: {
      app: 'global',
      name: 'saml_cert'
    }
  });
  if (!spCert) {
    throw new Error('No Init openssl X509 cert');
  }
  const certAndKey = JSON.parse(spCert.value);

  const res = await app.curl(config.idpMetadataUrl);
  const idpMetadata = await parser(res.data.toString());

  const samlConfig = {
    passReqToCallback: true,
    entryPoint: idpMetadata.sso.redirectUrl,

    issuer: 'http://127.0.0.1:5680',
    logoutUrl: idpMetadata.slo.redirectUrl,
    logoutCallbackUrl: '/passport/saml/logout',

    cert: idpMetadata.signingKeys[0],
    signatureAlgorithm: 'sha256',
    privateCert: certAndKey.key,
    decryptionPvk: certAndKey.key
  };

  const strategy = new Strategy(samlConfig, (req, user, done) => {
    app.passport.doVerify(req, user, done);
  });

  strategy.getLogoutUrl = async req => new Promise((reslove, reject) => {
    strategy.logout(req, (err, url) => {
      if (err) {
        reject(err);
      } else {
        reslove(url);
      }
    });
  });

  strategy.getMetadata = ({ host }) => utils.getMetadata({
    host,
    cert: certAndKey.cert,
  });

  strategy.mount = (router) => {
    router.get('/passport/saml', async (ctx, next) => {
      await app.passport.authenticate('saml')(ctx);
    });
    router.post('/passport/saml', async (ctx, next) => {
      await app.passport.authenticate('saml')(ctx);
      const session = ctx.helper.getSymbolValue(ctx, 'context#_contextSession');
      if (!session) { return; }
      ctx.user.SPClientId = session.externalKey;
      ctx.model.Session.create({
        sp_client_id: ctx.user.SPClientId,
        idp_client_id: ctx.user.IDPClientId,
        user_id: ctx.user.email,
      });
    });
    router.get('/passport/saml/logout', async (ctx, next) => {
      if (!ctx.req.user) {
        ctx.redirect('/');
        return;
      }
      ctx.req.user.sessionIndex = ctx.req.user.IDPClientId;
      const idpLogoutUrl = await strategy.getLogoutUrl(ctx.req);
      await app.curl(idpLogoutUrl);
      ctx.logout();
      ctx.redirect('/');
    });
    router.post('/passport/saml/logout', async (ctx, next) => {
      console.log(99999, ctx.request.body);
      strategy._saml.validatePostRequest(ctx.request.body, function() {
        console.log(222, arguments);
      });
      ctx.body = 'OK';
    });
    router.get('/passport/saml/metadata', async (ctx, next) => {
      const origin = ctx.origin;
      ctx.body = await strategy.getMetadata({ host: origin });
      ctx.set('Content-Type', 'application/xml');
    });
  };

  app.passportSaml = strategy;
  app.passport.use(strategy);
  // app.passportSaml.mount(app.router);
};
