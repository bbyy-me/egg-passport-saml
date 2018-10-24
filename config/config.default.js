'use strict';

exports.passportSaml = {
  idpMetadataUrl: 'https://idp_example.tfcloud.com/sso/saml2.0/metadata',
  issuer: 'https://sp_example.tfcloud.com',
  cert: '',
  key: '',
  mountRouter: true, // !!!此插件绑定路由的过程是异步的
  routersNOTMount: [],
  cacheProvider: null,
};
