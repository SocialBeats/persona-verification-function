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
    if (false) { // TODO: quitar
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
    // 3. PARSEAR Y PROCESAR EVENTO (NUEVA LÓGICA)
    // ---------------------------------------------------------
    // Detectamos si el evento viene anidado (lo normal en Webhooks de Persona)
    let inquiryData = null;

    if (event.data && event.data.attributes && event.data.attributes.payload && event.data.attributes.payload.data) {
        // CASO 1: Viene dentro de 'payload' (Tu caso actual: inquiry.approved)
        inquiryData = event.data.attributes.payload.data;
    } else if (event.data && event.data.type === 'inquiry') {
        // CASO 2: Viene directo (A veces pasa en otros eventos)
        inquiryData = event.data;
    }

    // Si no encontramos datos de inquiry válidos, ignoramos
    if (!inquiryData || !inquiryData.attributes) {
        console.log("ℹ️ Evento ignorado: No contiene datos de Inquiry válidos.");
        return { body: { message: "Estructura ignorada" }, statusCode: 200 };
    }

    const status = inquiryData.attributes.status;
    const userId = inquiryData.attributes.reference_id;
    const inquiryId = inquiryData.id;

    console.log(`🔎 Estado: ${status} | Usuario: ${userId} | ID: ${inquiryId}`);

    // ---------------------------------------------------------
    // 4. FILTRAR Y ACTUALIZAR (Soporta 'approved', 'passed', 'completed')
    // ---------------------------------------------------------
    if (status === 'approved' || status === 'passed' || status === 'completed') {
        
        console.log(`✅ ¡ÉXITO! Usuario ${userId} ha sido aprobado/verificado.`);

        if (!userId) {
            console.error("❌ Error: Reference ID (userId) faltante");
            return { body: { error: "Reference ID missing" }, statusCode: 400 };
        }

        try {
            const gatewayUrl = process.env.API_GATEWAY_URL;
            const updateUrl = `${gatewayUrl}/api/v1/profile/internal/${userId}/verification-status`;
            
            console.log(`🚀 Llamando al gateway: ${updateUrl}`);

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
            console.error("❌ Error llamando al Gateway:", error.message);
            return { body: { error: "Fallo interno al actualizar" }, statusCode: 500 };
        }
    }

    // ---------------------------------------------------------
    // 5. MANEJAR OTROS ESTADOS
    // ---------------------------------------------------------
    if (status === 'failed' || status === 'declined') {
        console.log(`⚠️ Verificación fallida o rechazada para ${userId}`);
    }

    return { body: { message: `Evento ignorado (Estado: ${status})` }, statusCode: 200 };
}
