'use strict';

exports.passportSaml = {
  enable: true,
  idpHost: 'http://idp.example.com',
  idpMetadataUrl: 'https://idp.example.com/sso/saml2.0/metadata',
  issuer: 'http://sp.example.com',
  cert: '',
  key: '',
  mountRouter: true, // !!!此插件绑定路由的过程是异步的，定义路由时要把passport用的路由避开。
  routersNOTMount: [],
  cacheProvider: null,
  acceptedClockSkewMs: 0,
  routers: [{
    controller: 'metadata',
    enable: true, // 如果enable指明为false，则不绑定
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
  }],
};
