'use strict';

const { promisify } = require('util');
const exec = promisify(require('child_process').exec);

module.exports = async (agent) => {
  if (agent.model) {
    await agent.model.sync();
    const find = await agent.model.Setting.findOne({
      where: {
        app: 'global',
        name: 'saml_cert'
      }
    });
    if (find === null) {
      const output = await exec('openssl req -x509 -new -newkey rsa:2048 -nodes -subj \'/C=CN/ST=Beijing/L=Haidian/O=TFCloud/CN=UDS\' -days 7300 -pubkey');
      const key = output.stdout.match(/-----BEGIN PRIVATE KEY-----[\s\S]+-----END PRIVATE KEY-----/)[0];
      const cert = output.stdout.match(/-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/)[0];
      const pubkey = output.stdout.match(/-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----/)[0];
      await agent.model.Setting.create({
        app: 'global',
        name: 'saml_cert',
        value: JSON.stringify({
          cert,
          key,
          pubkey,
        })
      });
    }
  }
};
