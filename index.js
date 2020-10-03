const crypto = require('crypto')

const encode = value => Buffer.from(value).toString('base64')
const decode = value => Buffer.from(value, 'base64').toString('ascii')

const makeHash = (secret, value) => crypto.createHmac('sha256', secret).update(value).digest('hex')

exports.sign = function sing(secret, value) {
  return `${encode(makeHash(secret, value))}.${encode(value)}`
}

exports.unsign = function unsign(secret, token) {
  const parts = token.split('.')

  if (parts.length !== 2) {
    throw new Error('Wrong signature')
  }

  const signature = decode(parts[0])
  const payload = decode(parts[1])

  const expected = makeHash(secret, payload)

  if (!crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected),
    )) {
    throw new Error('Wrong signature')
  }

  return payload
}
