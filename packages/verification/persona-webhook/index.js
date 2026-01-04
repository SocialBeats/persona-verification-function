const crypto = require('crypto');
const axios = require('axios');

/**
 * Verifica la firma HMAC del webhook de Persona.
 * @param {string} payload - El body raw del webhook (string)
 * @param {string} signature - El header 'persona-signature'
 * @param {string} secret - Tu Webhook Secret de Persona
 * @returns {boolean} - true si la firma es válida
 */
function verifyPersonaSignature(payload, signature, secret) {
    if (!signature || !secret) {
        return false;
    }

    // Persona envía: t=timestamp,v1=signature
    const parts = signature.split(',');
    const timestamp = parts.find(p => p.startsWith('t='))?.split('=')[1];
    const v1Signature = parts.find(p => p.startsWith('v1='))?.split('=')[1];

    if (!timestamp || !v1Signature) {
        return false;
    }

    // Crear el mensaje a verificar: timestamp.payload
    const signedPayload = `${timestamp}.${payload}`;
    
    // Calcular HMAC-SHA256
    const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(signedPayload)
        .digest('hex');

    // Comparación segura contra timing attacks
    try {
        return crypto.timingSafeEqual(
            Buffer.from(v1Signature, 'hex'),
            Buffer.from(expectedSignature, 'hex')
        );
    } catch (e) {
        return false;
    }
}

/**
 * Función principal para DigitalOcean Functions.
 * Gestiona el webhook de Persona y actualiza el estado de verificación del usuario.
 */
exports.main = async function(args) {
    // ---------------------------------------------------------
    // 1. OBTENER HEADERS Y VALIDAR FIRMA
    // ---------------------------------------------------------
    const headers = args.http ? args.http.headers : {};
    const signature = headers['persona-signature'];
    const webhookSecret = process.env.PERSONA_WEBHOOK_SECRET;

    // En DO Functions, el body raw viene como string en __ow_body si existe
    // Si no, tenemos que reconstruirlo del objeto args
    // ---------------------------------------------------------
    // 1. OBTENER EL RAW BODY CORRECTAMENTE (NUEVO)
    // ---------------------------------------------------------
    let rawBody = args.__ow_body;

    if (args.__ow_isBase64 && rawBody) {
        rawBody = Buffer.from(rawBody, 'base64').toString('utf8');
    }

    if (!rawBody) {
        console.warn('⚠️ __ow_body no encontrado. Intentando reconstruir JSON...');
        const cleanArgs = { ...args };
        delete cleanArgs.http;
        delete cleanArgs.__ow_headers;
        delete cleanArgs.__ow_path;
        delete cleanArgs.__ow_method;
        delete cleanArgs.__ow_body;
        delete cleanArgs.__ow_isBase64;
        rawBody = JSON.stringify(cleanArgs);
    }

    // Validar firma de Persona
    if (!verifyPersonaSignature(rawBody, signature, webhookSecret)) {
        console.error('❌ Firma de Persona inválida o faltante');
        return { 
            body: { error: 'Invalid webhook signature' }, 
            statusCode: 401 
        };
    }

    console.log('✅ Firma de Persona verificada correctamente');

    // ---------------------------------------------------------
    // 2. PARSEAR EVENTO
    // ---------------------------------------------------------
    // El cuerpo ya viene parseado en args (DO Functions lo hace automáticamente)
    const event = args;

    console.log('Evento recibido de Persona:', JSON.stringify(event.data ? event.data.id : 'sin id'));

    // ---------------------------------------------------------
    // 3. FILTRAR EVENTO (Solo si pasó la verificación)
    // ---------------------------------------------------------
    if (event.data && event.data.attributes && 
       (event.data.attributes.status === 'passed' || event.data.attributes.status === 'completed')) {
        
        const userId = event.data.attributes.reference_id;
        const inquiryId = event.data.id;

        console.log(`✅ Usuario ${userId} verificado. Inquiry: ${inquiryId}`);

        if (!userId) {
            console.error("Reference ID (userId) faltante en el evento");
            return { body: { error: "Reference ID missing" }, statusCode: 400 };
        }

        try {
            // ---------------------------------------------------------
            // 4. LLAMADA AL API GATEWAY
            // ---------------------------------------------------------
            const gatewayUrl = process.env.API_GATEWAY_URL;
            const updateUrl = `${gatewayUrl}/api/v1/profile/internal/${userId}/verification-status`;
            
            console.log(`Llamando al gateway: ${updateUrl}`);

            await axios.put(updateUrl, 
                { 
                    status: 'VERIFICADO',
                    provider_id: inquiryId
                },
                {
                    headers: {
                        'x-internal-api-key': process.env.INTERNAL_API_KEY,
                        'Content-Type': 'application/json'
                    }
                }
            );

            return { body: { message: "Perfil actualizado correctamente" }, statusCode: 200 };

        } catch (error) {
            console.error("Error llamando al Gateway:", error.message);
            if (error.response) {
                console.error("Detalles respuesta error:", error.response.status, error.response.data);
            }
            return { body: { error: "Fallo interno al actualizar" }, statusCode: 500 };
        }
    }

    // ---------------------------------------------------------
    // 5. MANEJAR OTROS ESTADOS
    // ---------------------------------------------------------
    if (event.data && event.data.attributes && event.data.attributes.status === 'failed') {
        console.log(`⚠️ Verificación fallida para evento ${event.data.id}`);
    }

    // Respondemos OK para que Persona no reintente
    return { body: { message: "Evento ignorado (no es 'passed'/'completed')" }, statusCode: 200 };
}
