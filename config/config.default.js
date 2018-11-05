'use strict';

exports.passportSaml = {
  idpMetadataPath: '/sso/saml2.0/metadata',
  idpConfigPath: '/public/config',

  idpHost: 'http://id.ustack.top',
  issuer: 'http://uos.ustack.top',
  cert: '',
  key: '',
  mountRouter: true, // !!!此插件绑定路由的过程是异步的，定义路由时要把passport用的路由避开。
  routersNOTMount: [],
  cacheProvider: null,
};
