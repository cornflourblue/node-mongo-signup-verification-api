const express = require('express');
const router = express.Router();
const Joi = require('joi');
const authorize = require('_middleware/authorize')
const Role = require('_helpers/role');
const utilitiesService = require('./utilities.service');
const validateRequest = require('_middleware/validate-request');

module.exports = router;

// routes
router.post('/enable/:id', authorize(Role.Admin), enable);
router.post('/disable/:id', authorize(Role.Admin), disable);
router.get('/', authorize(Role.Admin), getAll);
router.get('/:id', authorize(Role.Admin), getById);
router.post('/', authorize(Role.Admin), createSchema, create);
router.put('/:id', authorize(Role.Admin), updateSchema, update);
router.delete('/:id', authorize(Role.Admin), _delete);

function enable(req, res, next) {
    utilitiesService.enable(req.params.id)
        .then(() => res.json({ message: 'Utility enabled' }))
        .catch(next);
}

function disable(req, res, next) {
    utilitiesService.disable(req.params.id)
        .then(() => res.json({ message: 'Utility disabled' }))
        .catch(next);
}

function getAll(req, res, next) {
    utilitiesService.getAll()
        .then(utilities => res.json(utilities))
        .catch(next);
}

function getById(req, res, next) {
    utilitiesService.getById(req.params.id)
        .then(utility => utility ? res.json(utility) : res.sendStatus(404))
        .catch(next);
}

function createSchema(req, res, next) {
    const schema = Joi.object({
        name: Joi.string().required(),
        status: Joi.boolean().required()
    });
    validateRequest(req, next, schema);
}

function create(req, res, next) {
    utilitiesService.create(req.body)
        .then(utility => res.json(utility))
        .catch(next);
}

function updateSchema(req, res, next) {
    const schemaRules = {
        name: Joi.string().empty(''),
        status: Joi.boolean().empty('')
    };

    const schema = Joi.object(schemaRules);
    validateRequest(req, next, schema);
}

function update(req, res, next) {
    utilitiesService.update(req.params.id, req.body)
        .then(utility => res.json(utility))
        .catch(next);
}

function _delete(req, res, next) {
    utilitiesService.delete(req.params.id)
        .then(() => res.json({ message: 'Utility deleted successfully' }))
        .catch(next);
}