// mongoose
const mongoose = require('mongoose');
// encripta passwords
const bcrypt = require('bcryptjs');
// JWT
const jwt = require('jsonwebtoken');
// crypto 
const crypto = require('crypto');

const UserSchema = new mongoose.Schema({
   email: {
      type: String,
      trim: true,
      lowercase: true,
      required: [true, 'Por favor agrega un email'],
      unique: [true, 'Ese correo ya existe, ¿Olvidaste tu contraseña?'],
      match: [
         /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
         "Por favor agrega un email válido",
      ]
   },
   nombre: { type: String, trim: true, required: [true, 'Por favor agrega un Nombre'] },
   telefonos: {
      type: [String],
      trim: true
   },
   foto: {
      b64: String,
      mimetype: String
   },
   role: {
      type: String,
      enum: ['usuario', 'emisor']
   },
   password: {
      type: String,
      required: [true, 'Por favor ingresa una contraseña'],
      minlength: 3,
      select: false
   },
   resetPasswordToken: String,
   resetPasswordExpire: Date,
   _date: Date,
   _2FA: {
      active: { type: Boolean, default: false },
      pinlock: {
         type: Number,
         select: false,
         minlength: 6,
         maxlength: 6,
         default: null,
      }
   },
   compras: {
      modalidad: { type: String, enum: ['suscripcion', 'folios'] },
      suscripcion: {
         plan_activo: String,
         fecha_inicio: Date,
         fecha_fin: Date,
         timbres_restantes: Number,
      },
      folios: {
         plan_activo: String,
         fecha_inicio: Date,
         fecha_fin: Date,
         timbres_restantes: Number,
      },
      envio_sms: { type: Number, default: 0 },
      max_empresas: { type: Number, default: 1 },
      historial: [{
         item_comprado: String,
         fecha_de_compra: Date,
         precio: Number,
         detalle: String,
      }]
   },
   notas: [{
      fecha: Date,
      titulo: String,
      contenido: String,
      respuesta: String,
      open: { type: Boolean, default: false },
      opened_by: { type: String, trim: true },
   }],
   push_notifications: [{
      fecha: Date,
      titulo: String,
      contenido: String,
      respuesta: String,
      open: { type: Boolean, default: false },
   }],
   perfiles_fact: [{
      rfc: { type: String, uppercase: true, trim: true },
      razon_social: String,
      telefonos: [String],
      email: [String],
      direccion: {
         calle: String,
         numero_ext: String,
         numero_int: String,
         asentamiento: String,
         codigo_postal: String,
         municipio: String,
         estado: String,
         ciudad: String,
      },
   }]

}, //UserSchema
   /// virtuals
   {
      toJSON: { virtuals: true },
      toObject: { virtuals: true }
   }
)// end Schema 

// middleware

// guarda password encryptado
UserSchema.pre('save', async function (next) {
   if (!this.isModified('password')) {
      next();
   }
   // change Date to my local date
   let now = new Date();
   this._date = now.setHours(now.getHours() - 6);

   /// hash password
   const salt = await bcrypt.genSalt(10);
   this.password = await bcrypt.hash(this.password, salt);

});

// Sign JWT and return
UserSchema.methods.getJwtToken = function () {
   return jwt.sign({
      id: this._id,
      // foo: crypto.randomBytes(6).toString('hex'),
      // bar: crypto.randomBytes(6).toString('hex'),
   },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE })
}
// Match password
UserSchema.methods.matchPassword = async function (password) {
   return await bcrypt.compare(password, this.password);
}

// Reverse populate
UserSchema.virtual('_empresas', { // <<--este es el mombre virtual que tendra en la respuesta JSON
   ref: 'Empresa', // <<-- este es el modelo en el que vamos a buscar
   localField: '_id', // <<-- este es el VALOR del modelo actual que vamos a buscar  (en este caso un valor que existe en Empresa)
   foreignField: 'user_id', // <<-- este es el campo externo donde vamos a buscar (un campo que exista en el modelo Ticket)
   justOne: false
})

// token reset password
UserSchema.methods.getResetPassword = function () {
   // fecha ahora
   const now = new Date()
   // generate token
   const resetToken = crypto.randomBytes(24).toString('hex');
   // hash the token
   this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
   // set the expire
   this.resetPasswordExpire = now.setMinutes(now.getMinutes() + 7);

   console.log(resetToken);
   return resetToken;
}

module.exports = mongoose.model('User', UserSchema);