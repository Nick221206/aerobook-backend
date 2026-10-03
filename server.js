require('dotenv').config();
const express = require('express'), mongoose = require('mongoose'), bcrypt = require('bcryptjs'),
  jwt = require('jsonwebtoken'), cors = require('cors');
const { Schema, model } = mongoose;
const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*', allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key'], exposedHeaders: ['Idempotent-Replayed'] }));

/* ---------- Models (MongoDB Atlas) ---------- */
const strip = { transform: (_, r) => { delete r._id; delete r.__v; delete r.passwordHash; delete r.userId; delete r.idemKey; return r; } };
const User = model('User', new Schema({ name: String, email: { type: String, unique: true }, phone: String, passwordHash: String, admin: { type: Boolean, default: false } }, { toJSON: strip }));
const Flight = model('Flight', new Schema({ id: { type: Number, unique: true }, o: String, d: String, al: String, dep: Number, dur: Number, price: Number, occ: { type: [String], default: [] } }, { toJSON: strip }));
const bSchema = new Schema({ ref: { type: String, unique: true }, userId: Schema.Types.ObjectId, email: String, fid: Number, route: String, al: String, dep: Number, date: String,
  seats: [String], pax: [Object], total: Number, at: String, idemKey: String, status: { type: String, default: 'pending' } }, { toJSON: strip });
bSchema.index({ userId: 1, idemKey: 1 }, { unique: true });   // <- idempotency: one booking per (user, key)
const Booking = model('Booking', bSchema);
const Log = model('Log', new Schema({ msg: String, at: { type: Date, default: Date.now } }));

/* ---------- Helpers ---------- */
const MULT = { Economy: 1, Business: 2.2, First: 3.5 }, BAG = 40;
const VALID_SEAT = /^([1-5][A-D]|([6-9]|1[0-4])[A-F])$/;
const clsOf = s => { const r = parseInt(s); return r <= 2 ? 'First' : r <= 5 ? 'Business' : 'Economy'; };
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const sign = u => jwt.sign({ id: u.id, admin: u.admin }, process.env.JWT_SECRET, { expiresIn: '7d' });
const note = m => Log.create({ msg: m }).catch(() => {});

/* ---------- JWT middleware ---------- */
const auth = async (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = await User.findById(jwt.verify(t, process.env.JWT_SECRET).id);
    if (!req.user) throw new Error('no user');
    next();
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
};
const adminOnly = (req, res, next) => req.user.admin ? next() : res.status(403).json({ error: 'Admin only.' });

/* ---------- Auth ---------- */
app.post('/api/auth/signup', wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || name.trim().length < 2 || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6)
    return res.status(400).json({ error: 'Enter a name, a valid email and a 6+ character password.' });
  if (await User.findOne({ email: email.toLowerCase() })) return res.status(409).json({ error: 'Email already registered.' });
  const u = await User.create({ name: name.trim(), email: email.toLowerCase(), passwordHash: await bcrypt.hash(password, 10) });
  note('New signup: ' + u.email);
  res.status(201).json({ token: sign(u), user: u });
}));
app.post('/api/auth/login', wrap(async (req, res) => {
  const u = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
  if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.passwordHash))) return res.status(401).json({ error: 'Invalid email or password.' });
  note('Login: ' + u.email);
  res.json({ token: sign(u), user: u });
}));
app.get('/api/me', auth, (req, res) => res.json(req.user));
app.put('/api/me', auth, wrap(async (req, res) => {
  const name = String(req.body.name || '').trim(), phone = String(req.body.phone || '').trim();
  if (name.length < 2 || (phone && !/^[0-9+\-\s]{7,15}$/.test(phone))) return res.status(400).json({ error: 'Enter a name and a valid phone number.' });
  Object.assign(req.user, { name, phone }); await req.user.save(); res.json(req.user);
}));

/* ---------- Flights ---------- */
app.get('/api/flights', wrap(async (req, res) => {
  const q = {}; if (req.query.o) q.o = String(req.query.o); if (req.query.d) q.d = String(req.query.d);
  res.json(await Flight.find(q).sort('id'));
}));
app.get('/api/flights/:id', wrap(async (req, res) => {
  const f = await Flight.findOne({ id: +req.params.id });
  f ? res.json(f) : res.status(404).json({ error: 'Flight not found.' });
}));

/* ---------- Bookings: idempotent + double-booking safe ---------- */
app.post('/api/bookings', auth, wrap(async (req, res) => {
  const key = req.get('Idempotency-Key');
  if (!key || key.length < 8 || key.length > 100) return res.status(400).json({ error: 'Idempotency-Key header is required.' });
  const { flightId, seats, pax, date } = req.body;
  const f = await Flight.findOne({ id: +flightId });
  if (!f) return res.status(404).json({ error: 'Flight not found.' });
  if (!Array.isArray(seats) || !seats.length || seats.length > 6 || new Set(seats).size !== seats.length ||
      !seats.every(s => typeof s === 'string' && VALID_SEAT.test(s)) || !Array.isArray(pax) || pax.length !== seats.length)
    return res.status(400).json({ error: 'Invalid seats or passengers.' });
  const clean = pax.map(p => ({ name: String(p.name || '').trim(), age: +p.age, bag: [0, 10, 20, 30].includes(+p.bag) ? +p.bag : 0, meal: ['Veg', 'Non-veg', 'None'].includes(p.meal) ? p.meal : 'None' }));
  if (clean.some(p => p.name.length < 2 || !(p.age >= 0 && p.age <= 120))) return res.status(400).json({ error: 'Invalid passenger details.' });
  const total = seats.reduce((a, s, i) => a + f.price * MULT[clsOf(s)] + clean[i].bag * BAG, 0);   // price is computed on the server

  // Step 1: claim the idempotency key. A repeat request hits the unique index and gets the SAME booking back.
  let b;
  try {
    b = await Booking.create({ ref: 'AB' + Math.random().toString(36).slice(2, 8).toUpperCase(), userId: req.user.id, email: req.user.email,
      fid: f.id, route: f.o + '→' + f.d, al: f.al, dep: f.dep, date: String(date || ''), seats, pax: clean, total, at: new Date().toISOString().slice(0, 10), idemKey: key });
  } catch (e) {
    if (e.code !== 11000) throw e;
    const old = await Booking.findOne({ userId: req.user.id, idemKey: key });
    if (!old) return res.status(500).json({ error: 'Please retry.' });
    if (old.fid !== f.id || old.seats.join() !== seats.join()) return res.status(422).json({ error: 'This Idempotency-Key was used for a different booking.' });
    res.set('Idempotent-Replayed', 'true');
    return res.status(200).json(old);
  }
  // Step 2: reserve all seats in ONE atomic update; it only matches if none of them is already occupied.
  const r = await Flight.updateOne({ id: f.id, occ: { $nin: seats } }, { $push: { occ: { $each: seats } } });
  if (!r.modifiedCount) {
    await Booking.deleteOne({ _id: b._id });
    return res.status(409).json({ error: 'One of those seats was just taken. Please choose again.' });
  }
  b.status = 'confirmed'; await b.save();
  note(`Booking ${b.ref} (${b.route}, ₹${Math.round(total)})`);
  res.status(201).json(b);
}));
app.get('/api/bookings/mine', auth, wrap(async (req, res) => res.json(await Booking.find({ userId: req.user.id, status: 'confirmed' }).sort('-_id'))));

/* ---------- Admin ---------- */
const A = [auth, adminOnly];
const fv = b => { const o = String(b.o), d = String(b.d); return o !== d && /^[A-Z]{3}$/.test(o) && /^[A-Z]{3}$/.test(d) && b.dep >= 0 && b.dur > 0 && b.price > 0 ? { o, d, al: String(b.al), dep: +b.dep, dur: +b.dur, price: +b.price } : null; };
app.get('/api/admin/flights', A, wrap(async (q, r) => r.json(await Flight.find().sort('id'))));
app.get('/api/admin/bookings', A, wrap(async (q, r) => r.json(await Booking.find({ status: 'confirmed' }).sort('-_id'))));
app.get('/api/admin/log', A, wrap(async (q, r) => r.json((await Log.find().sort('-at').limit(30)).map(l => l.at.toLocaleString() + ' · ' + l.msg))));
app.post('/api/admin/flights', A, wrap(async (req, res) => {
  const v = fv(req.body); if (!v) return res.status(400).json({ error: 'Invalid flight data.' });
  const last = await Flight.findOne().sort('-id');
  const f = await Flight.create({ ...v, id: (last ? last.id : 0) + 1 }); note(`Added flight ${v.o}→${v.d}`); res.status(201).json(f);
}));
app.put('/api/admin/flights/:id', A, wrap(async (req, res) => {
  const v = fv(req.body); if (!v) return res.status(400).json({ error: 'Invalid flight data.' });
  const f = await Flight.findOneAndUpdate({ id: +req.params.id }, v, { new: true });
  if (!f) return res.status(404).json({ error: 'Flight not found.' }); note(`Edited flight ${v.o}→${v.d}`); res.json(f);
}));
app.delete('/api/admin/flights/:id', A, wrap(async (req, res) => { await Flight.deleteOne({ id: +req.params.id }); note('Deleted flight AB' + req.params.id); res.json({ ok: true }); }));
app.get('/', (q, r) => r.send('AeroBook API is running'));

/* ---------- Seed + start ---------- */
async function seed() {
  if (!(await Flight.countDocuments())) {
    const codes = ['BOM', 'DEL', 'BLR', 'HYD', 'MAA', 'GOI'], airlines = ['IndiGo', 'Air India', 'Akasa Air', 'SpiceJet'], all = [];
    for (let r = 1; r <= 14; r++) for (const c of (r <= 5 ? 'ABCD' : 'ABCDEF')) all.push(r + c);
    const docs = []; let id = 1;
    codes.forEach(o => codes.forEach(d => { if (o === d) return; for (let k = 0; k < 3; k++)
      docs.push({ id: id++, o, d, al: airlines[Math.floor(Math.random() * 4)], dep: 300 + Math.floor(Math.random() * 1000), dur: 90 + Math.floor(Math.random() * 100),
        price: Math.round((2800 + Math.random() * 6000) / 10) * 10, occ: all.filter(() => Math.random() < .25) }); }));
    await Flight.insertMany(docs);
  }
  const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (ADMIN_EMAIL && ADMIN_PASSWORD && !(await User.findOne({ email: ADMIN_EMAIL.toLowerCase() })))
    await User.create({ name: 'Admin', email: ADMIN_EMAIL.toLowerCase(), passwordHash: await bcrypt.hash(ADMIN_PASSWORD, 10), admin: true });
}
mongoose.connect(process.env.MONGODB_URI).then(seed).then(() => app.listen(process.env.PORT || 5000, () => console.log('AeroBook API ready')))
  .catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
