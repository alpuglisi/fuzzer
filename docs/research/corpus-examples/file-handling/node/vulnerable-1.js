/*
 * Excerpt from g0v/wiselike, proxy.js: multer storage config + the
 * `/users/:user/avatar` upload route. No fileFilter and no extension/
 * mime-type allowlist at all -- the uploaded file is written under its
 * original name (`file.originalname`). See manifest.yaml for repo/commit/
 * license provenance. Trimmed to the upload-relevant lines; unrelated
 * routes/config omitted.
 */

const express = require('express')
const bodyParser = require('body-parser')
const crypto = require('crypto')
const cors = require('cors')
const querystring = require('querystring')
const axios = require('axios')
const FD = require('form-data')
const fs = require('fs')
const multer = require('multer')
const storage = multer.diskStorage({
  destination: './uploads/',
  filename: function (req, file, cb) {
    crypto.pseudoRandomBytes(16, function (err, raw) {
      if (err) return cb(err)
      cb(null, file.originalname)
    })
  }
})
const upload = multer({ storage: storage })

app.post('/users/:user/avatar', upload.single('avatar'), (req, res) => {
  let sso = req.query.sso
  let sig = req.query.sig
  let profile = getLoginProfile(sso, sig)
  if (!profile) {
    return res.status(403).json({'errors': 'Please login'})
  }
  let me = profile.username
  let config_me = JSON.parse(JSON.stringify(config)) // deep-copy
  config_me.headers['Api-Username'] = me
  let config_file = JSON.parse(JSON.stringify(config)) // deep-copy
  delete config_file.headers['Content-Type']
  let form = new FD()
  form.append('files[]', fs.createReadStream('./uploads/' + req.file.originalname))
  form.append('type', 'avatar')
  form.append('user_id', profile.external_id)
  form.append('synchronous', 'true') // FIXME: is this needed?
  Object.assign(config_file.headers, form.getHeaders())
  /* upload avatar */
  axios.post(`uploads`, form, config_file)
    .then((val) => {
      let pickform = querystring.stringify({
        type: 'uploaded',
        upload_id: val.data.id
      })
      /* update user's avatar */
      return axios.put(`/users/${me}/preferences/avatar/pick`, pickform, config)
    })
    .then((val) => {
      res.send(val.data)
      // delete local image
      fs.unlink('./uploads/' + req.file.originalname, (err) => {
        if (err) {
          console.log('failed to delete local image')
        }
      })
    })
    .catch(error => {
      console.log(`fail to update avatar`)
      res.send(error)
    })
})
