'use strict';
module.exports = function(app) {
  const routers = [{
    controller: 'metadata',
    comment: '本服务展示信息的路径，用于在Identity Provider中注册服务',
    path: '/passport/saml/metadata',
    method: 'get',
    default: 'GET /passport/saml/metadata',
  },
  {
    controller: 'sso',
    comment: '用户从首页跳转到此路径时，系统向Identity Provider去验证',
    method: 'get',
    path: '/passport/saml',
    default: 'GET /passport/saml',
  },
  {
    controller: 'ssoCallback',
    comment: 'Identity Provider验证成功后的回调路径',
    method: 'post',
    path: '/passport/saml',
    default: 'POST /passport/saml',
  },
  {
    controller: 'logout',
    comment: '用户or前端访问此路径时，退出登录',
    path: '/passport/saml/logout',
    method: 'get',
    default: 'GET /passport/saml/logout',
  },
  {
    controller: 'slo',
    comment: 'Identity Provider向本服务发出登出消息时访问的路径',
    path: '/passport/saml/logout',
    method: 'post',
    default: 'POST /passport/saml/metadata',
  }];


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
          const idpLogoutUrl = await app.passportSaml.getLogoutUrl(ctx);
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
        app.passportSaml._saml.validatePostRequest(ctx.request.body, async function(err, res) {
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
  const { routersNOTMount = [] } = app.config.passportSaml;
  routers.forEach(router => {
    if (!router) return;

    const ctrl = controllers[router.controller];
    if (!ctrl) return;

    if (routersNOTMount.indexOf(router.controller) > -1) return;

    app.router[ctrl.method](router.path || ctrl.path, ctrl.controller);
  });
};
