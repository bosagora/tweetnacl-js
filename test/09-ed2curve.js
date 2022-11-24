var nacl = (typeof window !== 'undefined') ? window.nacl : require('../' + (process.env.NACL_SRC || 'nacl.min.js'));
nacl.util = require('tweetnacl-util');
var test = require('tape');

test('ed2curve.convertKeyPair (seed)', function(t) {
    var i, mySeed = new Uint8Array(32);
    for (i = 0; i < 32; i++) mySeed[i] = i;
    var peerSeed = new Uint8Array(32);
    for (i = 0; i < 32; i++) peerSeed[i] = i+100;

    var signKey = nacl.sign.keyPair.fromSeed(mySeed);
    var dhKeys = nacl.ed2curve(signKey);
    t.ok(dhKeys.publicKey, 'should convert public key');

    var dhPeerKeys = nacl.box.keyPair.fromSecretKey(peerSeed);
    var s1 = nacl.box.before(dhKeys.publicKey, dhPeerKeys.secretKey);
    var s2 = nacl.box.before(dhPeerKeys.publicKey, dhKeys.secretKey);
    t.equal(nacl.util.encodeBase64(s2), nacl.util.encodeBase64(s1));
    t.end();
});

test('ed2curve.convertKeyPair (random)', function(t) {
    var signKeys = nacl.sign.keyPair();
    var dhKeys = nacl.ed2curve(signKeys);
    var dhPeerKeys = nacl.box.keyPair();

    var message = 'I am converting keys!';
    var m = nacl.util.decodeUTF8(message);
    var n = nacl.randomBytes(24);
    var box = nacl.box(m, n, dhKeys.publicKey, dhPeerKeys.secretKey);
    var unbox = nacl.box.open(box, n, dhPeerKeys.publicKey, dhKeys.secretKey);
    t.ok(unbox, 'should open box');
    t.equal(nacl.util.encodeUTF8(unbox), message);
    t.end();
});

test('ed2curve.convertSecretKey and ed2curve.convertPublicKey (random)', function(t) {
    var mySignKeys = nacl.sign.keyPair();
    var theirSignKeys = nacl.sign.keyPair();

    var myDHPublicKey = nacl.ed2curve.convertPublicKey(mySignKeys.publicKey);
    var theirDHPublicKey = nacl.ed2curve.convertPublicKey(theirSignKeys.publicKey);

    t.equal(myDHPublicKey.length, 32);
    t.equal(theirDHPublicKey.length, 32);

    var myDHSecretKey = nacl.ed2curve.convertSecretKey(mySignKeys.secretKey);
    var theirDHSecretKey = nacl.ed2curve.convertSecretKey(theirSignKeys.secretKey);

    t.equal(myDHSecretKey.length, 32);
    t.equal(theirDHSecretKey.length, 32);

    var s1 = nacl.box.before(theirDHPublicKey, myDHSecretKey);
    var s2 = nacl.box.before(myDHPublicKey, theirDHSecretKey);
    t.equal(nacl.util.encodeBase64(s2), nacl.util.encodeBase64(s1));
    t.end();
});

test('ed2curve.convertPublicKey (invalid key)', function(t) {
    var invalidKey = new Uint8Array(32);
    for (var i = 0; i < 31; i++) invalidKey[i] = 0xff;
    var pk = nacl.ed2curve.convertPublicKey(invalidKey);
    t.equal(pk, null);
    t.end();
});

test('ed2curve.convertKeyPair (invalid key)', function(t) {
    var invalidKey = new Uint8Array(32);
    for (var i = 0; i < 31; i++) invalidKey[i] = 0xff;
    var keyPair = {
        publicKey: invalidKey,
        privateKey: new Uint8Array(32) // doesn't matter
    };
    var convertedKeyPair = nacl.ed2curve(keyPair);
    t.equal(convertedKeyPair, null);
    t.end();
});
