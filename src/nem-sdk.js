import Serialization from './serialization'
import convert from './convert'
import nacl from './nacl-fast'
import CryptoJS from 'crypto-js'

const currentFeeFactor = 0.05

let BinaryKey = function (keyData) {
  this.data = keyData
  this.toString = function () {
    return convert.ua2hex(this.data)
  }
}

let hashfunc = function (dest, data, dataLength) {
  let convertedData = convert.ua2words(data, dataLength)
  let hash = CryptoJS.SHA3(convertedData, {
    outputLength: 512
  })
  convert.words2ua(dest, hash)
}

let send = function (recipient, amount, message, privateKey) {
  let transferTransaction = {
    'amount': amount || 0,
    'recipient': recipient || '',
    'recipientPublicKey': '',
    'isMultisig': false,
    'multisigAccount': '',
    'message': message || '',
    'messageType': 1,
    'mosaics': []
  }

  let publicKey = new BinaryKey(new Uint8Array(nacl.lowlevel.crypto_sign_PUBLICKEYBYTES))
  let secretKey = convert.hex2ua_reversed(privateKey)
  nacl.lowlevel.crypto_sign_keypair_hash(publicKey.data, secretKey, hashfunc)
  let kp = {secretKey, publicKey}

  let entity = prepare(publicKey, transferTransaction, -104)

  let result = Serialization.serializeTransaction(entity)
  let signature = sign(result, kp)
  let obj = {
    'data': convert.ua2hex(result),
    'signature': signature.toString()
  }
  return announce(endpoint, JSON.stringify(obj))
}

let prepare = function (publicKey, tx, network) {
  let actualSender = publicKey.toString()
  let recipientCompressedKey = tx.recipient.toString()
  let amount = Math.round(tx.amount * 1000000)
  let message = {
    'type': 1,
    'payload': 'fe' + tx.message.toString()
  }
  let msgFee = calculateMessage(message)
  const testnetId = -104
  let due = network === testnetId ? 60 : 24 * 60
  let mosaics = null
  let mosaicsFee = null
  let entity = constructTx(actualSender, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network)
  return entity
}

let constructTx = function (senderPublicKey, recipientCompressedKey, amount, message, msgFee, due, mosaics, mosaicsFee, network) {
  let timeStamp = createNEMTimeStamp()
  let version = getVersion(1, network)
  const transferType = 0x101
  let data = txCommonPart(transferType, senderPublicKey, timeStamp, due, version)
  let fee = currentFeeFactor * calculateMinimum(amount / 1000000)
  let totalFee = Math.floor((msgFee + fee) * 1000000)
  let custom = {
    'recipient': recipientCompressedKey.toUpperCase().replace(/-/g, ''),
    'amount': amount,
    'fee': totalFee,
    'message': message,
    'mosaics': mosaics
  }
  let entity = extendObj(data, custom)
  return entity
}

let calculateMinimum = function (numNem) {
  let fee = Math.floor(Math.max(1, numNem / 10000))
  return fee > 25 ? 25 : fee
}

let extendObj = function () {
  for (var i = 1; i < arguments.length; i++) {
    for (var key in arguments[i]) {
      if (arguments[i].hasOwnProperty(key)) {
        arguments[0][key] = arguments[i][key]
      }
    }
  }
  return arguments[0]
}

let txCommonPart = function (txtype, senderPublicKey, timeStamp, due, version, network) {
  return {
    'type': txtype || '',
    'version': version || '',
    'signer': senderPublicKey || '',
    'timeStamp': timeStamp || '',
    'deadline': timeStamp + due * 60 || ''
  }
}

let getVersion = function (val, network) {
  if (network === 104) {
    return 0x68000000 | val
  } else if (network === -104) {
    return 0x98000000 | val
  }
  return 0x60000000 | val
}

let createNEMTimeStamp = function () {
  let NEM_EPOCH = Date.UTC(2015, 2, 29, 0, 6, 25, 0)
  return Math.floor((Date.now() / 1000) - (NEM_EPOCH / 1000))
}

let calculateMessage = function (message) {
  if (!message.payload || !message.payload.length) { return 0.00 }

  let length = message.payload.length / 2

  return currentFeeFactor * (Math.floor(length / 32) + 1)
}

let announce = function (serializedTransaction) {
  // Configure the request
  var options = {
    url: '/transaction/announce',
    method: 'POST',
    headers: json(serializedTransaction),
    json: JSON.parse(serializedTransaction)
  }
  // Send the request
  return Send(options)
}

let json = function (data) {
  return {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.from(data).byteLength
  }
}

// Signature
const sign = (data, kp) => {
  let sig = new Uint8Array(64)
  let hasher = new Hashobj()
  let r = nacl.lowlevel.crypto_sign_hash(sig, kp, data, hasher)
  if (!r) {
    throw new Error("Couldn't sign the tx, generated invalid signature")
  }
  return new BinaryKey(sig)
}

let getBalance = function (address) {
  return 3
}

/***
* Create an hasher object
*/
let Hashobj = function () {
  this.sha3 = CryptoJS.algo.SHA3.create({
    outputLength: 512
  })
  this.reset = function () {
    this.sha3 = CryptoJS.algo.SHA3.create({
      outputLength: 512
    })
  }

  this.update = function (data) {
    if (data instanceof BinaryKey) {
      let converted = convert.ua2words(data.data, data.data.length)
      this.sha3.update(converted)
    } else if (data instanceof Uint8Array) {
      let converted = convert.ua2words(data, data.length)
      this.sha3.update(converted)
    } else if (typeof data === 'string') {
      let converted = CryptoJS.enc.Hex.parse(data)
      this.sha3.update(converted)
    } else {
      throw new Error('unhandled argument')
    }
  }

  this.finalize = function (result) {
    let hash = this.sha3.finalize()
    convert.words2ua(result, hash)
  }
}

module.exports = {
  getBalance,
  send
}
