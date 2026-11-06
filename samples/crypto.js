const crypto = require('crypto');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ecdh = crypto.createECDH('prime256v1');
const digest = crypto.createHash('md5').update('hello').digest('hex');

// TODO: move to ML-KEM (X25519MLKEM768) for key exchange