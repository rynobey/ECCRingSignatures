function ring() {
  let object = {};
  
  let bn = require('bn.js');
  let crypto = require('crypto');
  let DRBG = require('hmac-drbg');
  let hash = require('hash.js');
  let randomInt = require('random-int');
  let EC = require('elliptic').ec;
  let ec = new EC('secp256k1');

  // Initialization of DRBG
  object.r = new DRBG({
    hash: hash.sha256,
    entropy: 'sasldfkjhfaleufhalkfjgvnslurhgglkauweyfgkasjdhfkayefgaksjhdfakjyhkaywebfkjasebfkjasdhbflafaksjehfbakljehfbgakjsehfbakjsdhbfakljebvlajwkebfalskjebfalksjdfblaksjdfhbalksjefbalkjj',
    nonce: '' + randomInt(10000000000000000000000000),
    pers: 'kajhbkfuyawegfkjajshbdefkajyhefkauywebbfkjashebfkajeshbfkajehbfak'
  });

  // Initialization of shared key for trapdoor
  let sharedPrivKey = new bn(object.r.generate(32, 'hex'), 16);
  object.sharedKeyPair = ec.keyFromPrivate(sharedPrivKey);

  // Trapdoor function - easy in one direction, very hard in other, unless private key is known
  // In this case (using ECC), x needs to be mapped to a point on the elliptic curve used.
  function f(x, pubKey, sharedPrivKey) {
    return addBToA(x, ec.keyFromPublic(pubKey.mul(sharedPrivKey)));
  }

  // Inverse trapdoor function - only if privKey is known. The input y needs to be a point on
  // the elliptic curve used.
  function f_p(y, privKey, sharedPubKey) {
    let temp = ec.keyFromPublic(sharedPubKey.mul(privKey))
    return subtractBFromA(y, temp);
  }

  // This is needed if trapdoors with different domain sizes are used in the ring signature.
  // Stubbed for now, since initially all trapdoors used will have the same domain size.
  function g(m) {
    return m;
  }

  function permute(m) {
    let sha1 = crypto.createHash('sha1');
    sha1.update(m);
    return sha1.digest('hex');
  }

  // Symmetric encryption algorithm. The input x should be a point on the elliptic curve used.
  function E(x, m) {
    let privKey = new bn(permute(m), 16);
    //let keyPair = ec.keyFromPrivate(privKey);
    return ec.keyFromPublic(x.getPublic().mul(privKey));
  }

  // Takes as input a keyPair (privKey may be null)
  function negate(pos) {
    return ec.keyFromPublic(pos.getPublic().mul(new bn(-1, 10)));
  }

  // Takes as input two key pairs
  function subtractBFromA(a, b) {
    b = negate(b);
    return addBToA(a, b);
  }

  // Takes as input two key pairs
  function addBToA(a, b) {
    return ec.keyFromPublic(a.getPublic().add(b.getPublic()));
  }

  // Uses the key at index z to sign message m
  function sign(k, m, z) {
    let sTemp;
    let upriv;
    let u = [];
    let v = [];
    let y = [];
    let s = [];
    upriv = new bn(object.r.generate(32, 'hex'), 16);
    u[z] = ec.keyFromPrivate(upriv);
    v[(z+1)%k.length] = E(u[z], m);
    for (let i = (z+1); i < (z+k.length); i++) {
      let index = i % k.length;
      sTemp = ec.keyFromPrivate(new bn(object.r.generate(32, 'hex'), 16));
      s[index+1] = ec.keyFromPublic(sTemp.getPublic());
      y[index] = f(s[index+1], k[index].getPublic(), object.sharedKeyPair.getPrivate());
      u[index] = addBToA(v[index], y[index]);
      v[(index+1)%k.length] = E(u[index], m);
    }
    y[z] = subtractBFromA(u[z], v[z]);
    s[z+1] = f_p(y[z], k[z].getPrivate(), object.sharedKeyPair.getPublic());
    s[0] =  v[0];
    return s;
  }

  // Verifies a ring signature s on message m using keys k
  function verify(k, m, s) {
    let y = [];
    for (let i = 0; i < k.length; i++) {
      y[i] = f(s[i+1], k[i].getPublic(), object.sharedKeyPair.getPrivate());
    }
    let indices = Array.from(Array(k.length).keys());
    let result = indices.reduce(function(total, current) {
      return E(addBToA(total, y[current]), m);
    }, s[0]);
    return result.getPublic().eq(s[0].getPublic());
  }

  // Tests invertible trapdoor function f (given knowledge of private key)
  function test1() {
    let privKey = new bn(object.r.generate(32, 'hex'), 16);
    let keyPair = ec.keyFromPrivate(privKey);

    let x = ec.keyFromPrivate(new bn(5, 10));
    let y = f(x, keyPair.getPublic(), object.sharedKeyPair.getPrivate());
    let xp = f_p(y, keyPair.getPrivate(), object.sharedKeyPair.getPublic());

    console.log(x.getPublic().eq(xp.getPublic()))
  }

  // Tests signature generation and verification
  function test2() {
    let key1 = ec.genKeyPair();
    let key2 = ec.genKeyPair();
    let key3 = ec.genKeyPair();
    let keyPairs1 = [
      key1,
      key2
    ];
    let keyPairs2 = [
      key1,
      key2
    ];
    let msg1 = "veritaserum";
    let msg2 = "veritaserum";
    let s = sign(keyPairs1, msg1, 0);
    console.log(verify(keyPairs2, msg2, s));
  }
  
  object.Sign = sign;
  object.Verify = verify;
  object.Test1 = test1;
  object.Test2 = test2;
  return object;
}

module.exports = ring;
