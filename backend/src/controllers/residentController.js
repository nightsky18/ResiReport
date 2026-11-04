const bcrypt = require('bcryptjs');
const User = require('../models/User');
const { BCRYPT_ROUNDS } = require('../config/env');

// Neutraliza metacaracteres antes de interpolar entrada de usuario en un RegExp.
const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// GET /api/residents
const getResidents = async (req, res, next) => {
  try {
    const { search, isActive } = req.query;
    const filter = { rol: 'resident' };

    if (search) {
      filter.$or = [
        { nombre: { $regex: search, $options: 'i' } },
        { correo: { $regex: search, $options: 'i' } },
        { apartamento: { $regex: search, $options: 'i' } },
      ];
    }

    if (isActive !== undefined) {
      filter.isActive = isActive === 'true';
    }

    const residents = await User.find(filter).select('-password');
    res.status(200).json({ ok: true, data: residents, total: residents.length });
  } catch (error) {
    next(error);
  }
};

// GET /api/residents/:id
const getResidentById = async (req, res, next) => {
  try {
    const resident = await User.findOne({ _id: req.params.id, rol: 'resident' }).select('-password');
    if (!resident) {
      return res.status(404).json({ ok: false, message: 'Residente no encontrado' });
    }
    res.status(200).json({ ok: true, data: resident });
  } catch (error) {
    next(error);
  }
};

// POST /api/residents — HU-03
const createResident = async (req, res, next) => {
  try {
    const {
      nombre,
      correo,
      password,
      torre,
      apartamento,
      telefono,
      tipoResidente,
      isActive,
    } = req.body;

    // Campos obligatorios incluyendo estado (isActive)
    if (!nombre || !correo || !password || !torre || !apartamento || isActive === undefined) {
      return res.status(400).json({
        ok: false,
        message: 'nombre, correo, password, torre, apartamento y estado son obligatorios',
      });
    }

    // Correo único en el sistema
    const emailExists = await User.findOne({ correo: correo.toLowerCase() });
    if (emailExists) {
      return res.status(409).json({
        ok: false,
        message: 'El correo ya está registrado en el sistema',
      });
    }

    // Apartamento duplicado — busca otro residente en la misma torre y apartamento.
    // La entrada se escapa para que solo coincida el texto literal (evita ReDoS).
    const torreExacta = escapeRegExp(torre.trim());
    const apartamentoExacto = escapeRegExp(apartamento.trim());
    const aptExists = await User.findOne({
      rol: 'resident',
      torre: { $regex: new RegExp(`^${torreExacta}$`, 'i') },
      apartamento: { $regex: new RegExp(`^${apartamentoExacto}$`, 'i') },
    });


    // Si existe, se permite crear pero se envía advertencia en la respuesta
    const warnings = [];
    if (aptExists) {
      warnings.push(`Ya existe un residente registrado en Torre ${torre}, Apto ${apartamento}`);
    }

const rounds = BCRYPT_ROUNDS;
    const hashedPassword = await bcrypt.hash(password, rounds);

    const resident = await User.create({
      nombre,
      correo: correo.toLowerCase(),
      password: hashedPassword,
      rol: 'resident',
      torre: torre.trim(),
      apartamento: apartamento.trim(),
      telefono: telefono?.trim() || null,
      tipoResidente: tipoResidente || null,
      isActive,
    });

    //  Confirmación visual — respuesta clara con datos del creado y advertencias 
    res.status(201).json({
      ok: true,
      message: 'Residente creado exitosamente',
      warnings,   // array vacío [] si no hay advertencias
      data: {
        id: resident._id,
        nombre: resident.nombre,
        correo: resident.correo,
        rol: resident.rol,
        torre: resident.torre,
        apartamento: resident.apartamento,
        tipoResidente: resident.tipoResidente,
        telefono: resident.telefono,
        isActive: resident.isActive,
        createdAt: resident.createdAt,
      },
    });
  } catch (error) {
    next(error);
  }
};

// PUT /api/residents/:id
const updateResident = async (req, res, next) => {
  try {
    const { password, ...rest } = req.body;

    if (password) {
  const rounds = BCRYPT_ROUNDS;
      rest.password = await bcrypt.hash(password, rounds);
    }

    const updated = await User.findOneAndUpdate(
      { _id: req.params.id, rol: 'resident' },
      rest,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updated) {
      return res.status(404).json({ ok: false, message: 'Residente no encontrado' });
    }

    res.status(200).json({ ok: true, data: updated });
  } catch (error) {
    next(error);
  }
};

// PATCH /api/residents/:id/status — HU-04
const toggleResidentStatus = async (req, res, next) => {
  try {
    const { isActive } = req.body;

    if (typeof isActive !== 'boolean') {
      return res.status(400).json({ ok: false, message: 'isActive debe ser true o false' });
    }

    const updated = await User.findOneAndUpdate(
      { _id: req.params.id, rol: 'resident' },
      { isActive },
      { new: true }
    ).select('-password');

    if (!updated) {
      return res.status(404).json({ ok: false, message: 'Residente no encontrado' });
    }

    res.status(200).json({ ok: true, data: updated });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getResidents,
  getResidentById,
  createResident,
  updateResident,
  toggleResidentStatus,
};
