const jwt = require('jsonwebtoken');
const asyncHandler = require('../middleware/asyncHandler');
const ErrorResponse = require('../utils/errorResponse');
const User = require('../models/User');

// Protect routes

exports.protect = asyncHandler(async (req, res, next)=>{
   let token;

   if (req.headers.authorization && 
      req.headers.authorization.startsWith('Bearer')) {
      ///
      token = req.headers.authorization.split(' ')[1];
   }//if
   else if (req.cookies.token) {
      token = req.cookies.token
   }

   // make sure token exists
   if (!token) {
      return next(new ErrorResponse(`No estas autorizado`, 401));
   }
   try {
      // verificar token
      // console.log('AUTH middleware');
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      // console.log(decoded);

      req_user = await User.findById(decoded.id);
      
      if (req_user == null) {
         return next(new ErrorResponse(`No estas autorizado`, 401));
      }

      req.user = req_user
      next();
            
   } catch (err) {
      return next(new ErrorResponse(`No estas autorizado`, 401));
   }
}) //////// protect


/// acces to roles especificos
exports.autorizado = (...roles) =>{
   return (req, res, next) =>{
      if (!roles.includes(req.user.role)) {
         return next(new ErrorResponse(`Usuario no autorizado`, 403));
      }
      next();
   }
}