const express = require('express');
const {
   allTickets,
   getTicket,
   addTicket,
   updateTicket,
   deleteTicket
} = require('../controllers/tickets');

// include other resource routers
const empresasRouter = require('./empresas');
//monta router
const router = express.Router({ mergeParams: true });
// protect
const { protect, autorizado } = require('../middleware/auth')

///

router.route('/')
   .get(protect, autorizado('emisor', 'admin'), allTickets)
   .post(protect, autorizado('emisor', 'admin'), addTicket);

router
   .route('/:id')
   .get(getTicket)
   .put(protect, autorizado('emisor', 'admin'), updateTicket)
   .delete(protect, autorizado('emisor', 'admin'), deleteTicket);



module.exports = router;