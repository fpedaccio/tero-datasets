"""Escenarios de ataque y controles negativos del buzon sintetico.

Cada escenario declara ``expected_layers``: las capas que *deberian* activarse.
La evaluacion no se limita a comprobar que el puntaje compuesto quedo alto, sino
que verifica que se encendieron las capas correctas por las razones correctas.
Un ataque homografico detectado unicamente por la capa semantica esta bien
clasificado y mal explicado, y para una plataforma cuyo diferencial es la
explicacion eso es una falla.

Los controles negativos son igual de importantes que los ataques. Un correo de
un proveedor nuevo que no pide nada sensible, o el gerente real pidiendo algo
con urgencia, tienen que quedar en verde. Sin ellos, un motor que marca todo
como riesgoso obtendria recall perfecto y seria inutil: son la unica forma de
medir el techo de falsos positivos que exige la Seccion 2.1.4.

Los ataques 1, 4 y 9 comparten una propiedad que conviene mostrar en la
exposicion: aprueban SPF, DKIM y DMARC. Son la evidencia concreta de lo que
argumenta la Seccion 2.1.3 sobre el limite de esos tres mecanismos frente al BEC.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from antiphishing.calendar_ar import resolve_business_stamp
from antiphishing.ingest.base import (
    Address,
    Attachment,
    AuthResults,
    NormalizedEmail,
)
from antiphishing.preprocess.pii import cbu_check_digits, cuit_check_digit
from antiphishing.seed.specs import ANDINA_DOMAIN, RIVAS_DOMAIN, TenantSpec

PHISHING = "phishing"
LEGITIMATE = "legitimo"


def make_cbu(bank_branch: str, account: str) -> str:
    """Arma un CBU valido (22 digitos) desde banco+sucursal y cuenta.

    Los identificadores de los escenarios se **calculan**, nunca se escriben a
    mano. El detector de PII valida el digito verificador de verdad, asi que un
    CBU inventado al azar no seria detectado y el escenario no probaria nada:
    pasaria como un ataque no detectado cuando en realidad el dato era falso.
    """
    dv1, dv2 = cbu_check_digits(bank_branch, account)
    return f"{bank_branch}{dv1}{account}{dv2}"


def make_cuit(first_ten: str) -> str:
    """Arma un CUIT valido con guiones desde sus primeros diez digitos."""
    return f"{first_ten[:2]}-{first_ten[2:]}-{cuit_check_digit(first_ten)}"


# CBU legitimo de Arriba Insumos, el que figura en el historial.
CBU_ARRIBA = make_cbu("0170099", "4500067890123")
# CBU del atacante: el que intenta que Andina use en su lugar.
CBU_ATACANTE = make_cbu("3110001", "9988776655443")
# CBU legitimo del proveedor Quimica del Sur.
CBU_QUIMICA = make_cbu("0290021", "7700112233445")

CUIT_ARRIBA = make_cuit("3068822991")
CUIT_QUIMICA = make_cuit("3070112233")


@dataclass(frozen=True, slots=True)
class Scenario:
    """Un correo de prueba con su verdad de referencia."""

    key: str
    label: str  # phishing | legitimo
    description: str
    mailbox: str
    sender_email: str
    sender_display: str
    subject: str
    body: str
    expected_layers: tuple[int, ...] = ()
    # Ubicacion temporal en dias habiles hacia atras y hora local, no en "horas
    # antes de ahora": una hora relativa depende del dia de la semana en que se
    # corra el seed, y un escenario pensado para las 4 AM de un dia habil
    # terminaba cayendo un domingo. Entonces la capa 4 se activaba por el fin de
    # semana en lugar de por la hora, que era lo que el escenario probaba.
    day_offset: int = 0
    hour: float = 10.0
    reply_to: str = ""
    mailer: str = "Microsoft Outlook 16.0"
    auth: AuthResults = AuthResults("pass", "pass", "pass")
    attachments: tuple[Attachment, ...] = ()
    thread_id: str | None = None
    in_reply_to: str | None = None
    # Envio declarado distinto del recibido (desfasaje del header Date).
    declared_offset_minutes: float = 0.0

    def to_email(self, tenant: TenantSpec, reference: datetime) -> NormalizedEmail:
        received = resolve_business_stamp(reference, self.day_offset, self.hour)
        sent = received - timedelta(minutes=self.declared_offset_minutes + 1)
        headers = {
            "X-Mailer": self.mailer,
            "Return-Path": f"<{self.sender_email}>",
            "Authentication-Results": (
                f"spf={self.auth.spf}; dkim={self.auth.dkim}; dmarc={self.auth.dmarc}"
            ),
        }
        if self.reply_to:
            headers["Reply-To"] = self.reply_to

        return NormalizedEmail(
            message_id=f"<atk-{self.key}-{tenant.id}@antiphishing.demo>",
            tenant_id=tenant.id,
            mailbox=self.mailbox,
            sender=Address(email=self.sender_email, display_name=self.sender_display),
            subject=self.subject,
            body_text=self.body.strip(),
            sent_at=sent,
            received_at=received,
            source="synthetic",
            recipients=(Address(email=self.mailbox),),
            reply_to=Address(email=self.reply_to) if self.reply_to else None,
            thread_id=self.thread_id,
            in_reply_to=self.in_reply_to,
            headers=headers,
            attachments=self.attachments,
            auth=self.auth,
            ground_truth=self.label,
            scenario=self.key,
            expected_layers=self.expected_layers,
        )


# --------------------------------------------------------------------------- #
# Ataques contra Distribuidora Andina
# --------------------------------------------------------------------------- #

ANDINA_SCENARIOS: tuple[Scenario, ...] = (
    # 1. BEC clasico por suplantacion del nombre visible. Aprueba SPF/DKIM/DMARC
    #    porque el correo sale realmente de Gmail: el vector no es tecnico.
    Scenario(
        key="bec_display_name_gerente",
        label=PHISHING,
        description="Suplantacion del nombre visible del socio gerente desde Gmail",
        mailbox=f"carla.gimenez@{ANDINA_DOMAIN}",
        sender_email="mbilbao.direccion@gmail.com",
        sender_display="Martin Bilbao",
        subject="Operacion confidencial - necesito tu ayuda",
        body=f"""
Carla, buen dia.

Estoy en una reunion con los abogados por una operacion que todavia no es
publica, asi que te pido reserva absoluta: no lo comentes con nadie del equipo
por ahora.

Necesito que prepares una transferencia de $ 2.850.000,00 hoy mismo antes de las
15 h. Te paso los datos del destinatario:

Titular: Consultora Lemos y Asociados
CBU: {CBU_ATACANTE}

Es una sena que no puede esperar a manana. Confirmame por este mail cuando este
hecha, no me llames que estoy en reunion.

Gracias,
Martin
        """,
        expected_layers=(2, 3, 5),
        day_offset=0,
        hour=9.5,
        mailer="Gmail",
    ),
    # 2. Dominio homografico del proveedor principal: arriba -> ariiba.
    Scenario(
        key="homografo_proveedor",
        label=PHISHING,
        description="Dominio parecido al del proveedor habitual (arriba -> ariiba)",
        mailbox=f"pagos@{ANDINA_DOMAIN}",
        sender_email="rodolfo.ferreyra@ariiba.com.ar",
        sender_display="Rodolfo Ferreyra",
        subject="Actualizacion de datos bancarios - Arriba Insumos SRL",
        body=f"""
Estimados:

Les informamos que a partir de este mes cambiamos de entidad bancaria. Por favor
actualicen nuestros datos en su sistema para las proximas ordenes de pago:

Titular: Arriba Insumos SRL
CUIT: {CUIT_ARRIBA}
CBU nuevo: {CBU_ATACANTE}

Les pedimos que las facturas pendientes se abonen a esta cuenta. El CBU anterior
({CBU_ARRIBA}) queda sin efecto.

Saludos cordiales,
Rodolfo Ferreyra
Administracion de ventas
Arriba Insumos SRL
        """,
        expected_layers=(2, 3, 5),
        day_offset=0,
        hour=11.0,
    ),
    # 3. Cambio de CBU insertado en un hilo de facturacion real.
    Scenario(
        key="cambio_cbu_en_hilo",
        label=PHISHING,
        description="Respuesta en hilo real de facturacion desde dominio con guion",
        mailbox=f"carla.gimenez@{ANDINA_DOMAIN}",
        sender_email="cobranzas@arriba-insumos.com.ar",
        sender_display="Cobranzas Arriba Insumos",
        subject="RE: Factura A-0004-00018472 - vencimiento",
        body=f"""
Carla, como estas.

Te confirmo el saldo de la factura A-0004-00018472 por $ 1.184.300,00.

Una aclaracion importante: por un tema de la cuenta anterior, el pago de esta
factura tiene que ir a la siguiente cuenta:

CBU: {CBU_ATACANTE}
Alias: lemos.consultora.pagos

Si ya generaste la orden con el CBU viejo avisame para frenarla.

Abrazo,
Cobranzas Arriba Insumos SRL
        """,
        expected_layers=(2, 3, 5),
        day_offset=-1,
        hour=15.5,
        thread_id="thread-factura-18472",
        in_reply_to="<hist-arriba-18472@arriba.com.ar>",
    ),
    # 4. Cuenta legitima comprometida: el remitente es real y la autenticacion
    #    pasa. Solo lo delata el desvio conductual y la hora.
    Scenario(
        key="cuenta_comprometida",
        label=PHISHING,
        description="Remitente legitimo comprometido: 3 AM, otro cliente de correo, sin firma",
        mailbox=f"pagos@{ANDINA_DOMAIN}",
        sender_email="rodolfo.ferreyra@arriba.com.ar",
        sender_display="Rodolfo Ferreyra",
        subject="pago pendiente",
        body=f"""
Hola necesito que hagan el pago hoy mismo a esta cuenta nueva porque la otra
esta bloqueada.

CBU {CBU_ATACANTE}

Es urgente, avisen cuando lo hagan.
        """,
        expected_layers=(1, 4, 5),
        day_offset=-1,
        hour=3.0,
        mailer="Thunderbird 45.0 (Windows/20160120)",
    ),
    # 5. Phishing masivo de banco con dominio de aspecto plausible.
    Scenario(
        key="phishing_banco_masivo",
        label=PHISHING,
        description="Suplantacion de entidad bancaria con dominio de aspecto plausible",
        mailbox=f"carla.gimenez@{ANDINA_DOMAIN}",
        sender_email="seguridad@bancodelplata-online.com",
        sender_display="Banco del Plata - Seguridad",
        subject="Su cuenta empresa sera suspendida en 24 horas",
        body="""
Estimado cliente,

Detectamos actividad inusual en su cuenta empresa. Por su seguridad la cuenta
sera suspendida en las proximas 24 horas si no valida su identidad.

Ingrese ahora para evitar la suspension:
https://bancodelplata-online.com/validacion/empresa

Si no realiza la validacion perdera el acceso a la banca electronica y sus pagos
programados seran cancelados.

Banco del Plata
Este es un mensaje automatico.
        """,
        expected_layers=(2, 3, 5),
        day_offset=0,
        hour=8.5,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "none", "fail"),
    ),
    # 6. Factura falsa con adjunto de macro.
    Scenario(
        key="factura_falsa_adjunto",
        label=PHISHING,
        description="Remitente desconocido con adjunto habilitado para macros",
        mailbox=f"facturacion@{ANDINA_DOMAIN}",
        sender_email="facturacion@servicios-corporativos-arg.com",
        sender_display="Servicios Corporativos",
        subject="Factura impaga 00184722 - reclamo formal",
        body="""
Buenos dias,

Adjuntamos el detalle de la factura impaga correspondiente al servicio prestado.
El vencimiento operó hace 45 dias y el expediente pasa a gestion judicial si no
se regulariza en 48 horas.

Abra el archivo adjunto para ver el detalle y las instrucciones de pago.

Departamento de Cobranzas
        """,
        expected_layers=(2, 5),
        day_offset=-1,
        hour=12.0,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("softfail", "none", "none"),
        attachments=(
            Attachment(
                filename="Factura_00184722.xlsm",
                content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
                size_bytes=184_320,
                sha256="3f8a1c9e" + "0" * 56,
            ),
        ),
    ),
    # 7. Suplantacion de organismo fiscal.
    Scenario(
        key="arca_falso",
        label=PHISHING,
        description="Suplantacion de ARCA con dominio .com.ar en lugar de .gob.ar",
        mailbox=f"carla.gimenez@{ANDINA_DOMAIN}",
        sender_email="notificaciones@arca-gob.com.ar",
        sender_display="ARCA - Notificaciones",
        subject="Intimacion de pago - vencimiento inminente",
        body="""
Contribuyente,

Se ha generado una intimacion de pago sobre su CUIT por diferencias detectadas
en las declaraciones juradas del ultimo periodo fiscal.

Descargue la intimacion completa desde el siguiente enlace y regularice su
situacion dentro de las 48 horas para evitar el embargo de cuentas:

http://arca-gob.com.ar/intimaciones/descargar

ARCA - Agencia de Recaudacion y Control Aduanero
        """,
        expected_layers=(2, 3, 5),
        day_offset=-1,
        hour=10.0,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "fail", "fail"),
    ),
    # 8. Spear phishing con reconocimiento previo del cargo.
    Scenario(
        key="spear_gift_cards",
        label=PHISHING,
        description="Spear phishing dirigido con datos del cargo, pide tarjetas de regalo",
        mailbox=f"veronica.paz@{ANDINA_DOMAIN}",
        sender_email="m.bilbao@direccion-andina.com",
        sender_display="Martin Bilbao - Direccion",
        subject="Reconocimiento para el equipo de deposito",
        body="""
Veronica,

Como venimos hablando, quiero reconocer el esfuerzo del equipo de deposito por
el cierre de trimestre. Necesito que compres 12 tarjetas de regalo de $ 50.000,00
cada una hoy a la tarde.

Comprensiblemente no quiero que se enteren antes, asi que manejalo directamente
conmigo y no lo pases por compras. Cuando las tengas mandame las fotos de los
codigos por este mail y despues te reintegro con el gasto de representacion.

Gracias por la discrecion.
Martin Bilbao
Direccion
        """,
        expected_layers=(2, 3, 5),
        day_offset=-1,
        hour=16.0,
    ),
    # 9. Homoglifo cirilico sobre el dominio propio del tenant: phishing lateral.
    Scenario(
        key="homoglifo_cirilico_interno",
        label=PHISHING,
        description="Dominio propio suplantado con caracter cirilico (phishing lateral)",
        mailbox=f"pagos@{ANDINA_DOMAIN}",
        sender_email="martin.bilbao@аndina.com.ar",
        sender_display="Martin Bilbao",
        subject="Autorizacion de pago urgente",
        body="""
Necesito que autorices el pago del proveedor nuevo antes del cierre de hoy.
Ya lo revise con contaduria, esta todo en orden.

Los datos estan en el archivo que te comparti. Confirmame cuando este.

Martin Bilbao
Socio gerente
Distribuidora Andina SA
        """,
        expected_layers=(2, 3, 5),
        day_offset=0,
        hour=10.0,
    ),
    # 10. Reply-To divergente: se lee como el proveedor, contesta al atacante.
    Scenario(
        key="reply_to_divergente",
        label=PHISHING,
        description="Remitente plausible con Reply-To hacia un dominio ajeno",
        mailbox=f"compras@{ANDINA_DOMAIN}",
        sender_email="marisa.lopez@quimicadelsur.com.ar",
        sender_display="Marisa Lopez",
        subject="Cotizacion revisada - responder a casilla alternativa",
        body=f"""
Hola, como estan.

Les envio la cotizacion revisada con el ajuste que pidieron. Estoy con problemas
en el correo de la empresa, asi que por favor respondan a mi casilla alternativa
que figura en este mensaje.

Aprovecho para confirmarles que la cuenta para el pago cambio:
CBU: {CBU_ATACANTE}

Quedo a la espera.
Marisa Lopez
Cuentas corporativas
Quimica del Sur SA
        """,
        expected_layers=(1, 5),
        day_offset=-1,
        hour=11.5,
        reply_to="m.lopez.cotizaciones@outlook-corporativo.com",
    ),
    # 11. Robo de credenciales de la suite de correo.
    Scenario(
        key="credenciales_workspace",
        label=PHISHING,
        description="Falsa expiracion de contrasena de la suite de correo",
        mailbox=f"lucia.ferrer@{ANDINA_DOMAIN}",
        sender_email="soporte@workspace-notificaciones.com",
        sender_display="Google Workspace",
        subject="Su contrasena expira hoy - accion requerida",
        body="""
Hola,

La contrasena de su cuenta corporativa expira hoy. Si no la actualiza en las
proximas horas perdera el acceso al correo y a los archivos compartidos.

Actualice su contrasena aqui:
http://workspace-notificaciones.com/andina.com.ar/renovar

Equipo de Google Workspace
        """,
        expected_layers=(2, 5),
        day_offset=0,
        hour=9.0,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "none", "fail"),
    ),
    # 12. Sustitucion de TLD: arriba.com.ar -> arriba.com
    Scenario(
        key="tld_swap_proveedor",
        label=PHISHING,
        description="Mismo nombre de proveedor con TLD distinto (.com en lugar de .com.ar)",
        mailbox=f"compras@{ANDINA_DOMAIN}",
        sender_email="rodolfo.ferreyra@arriba.com",
        sender_display="Rodolfo Ferreyra",
        subject="Lista de precios actualizada y nueva cuenta",
        body=f"""
Buen dia,

Adjunto la lista de precios con vigencia desde el lunes. Tambien les pido tomar
nota de nuestra nueva cuenta para transferencias:

CBU: {CBU_ATACANTE}

Cualquier duda quedo a disposicion.

Rodolfo Ferreyra
Administracion de ventas
Arriba Insumos SRL
Tel (011) 4310-8890
        """,
        expected_layers=(2, 3, 5),
        day_offset=-2,
        hour=14.0,
    ),
    # 13. Rafaga: tres mensajes del mismo remitente nuevo en pocos minutos.
    Scenario(
        key="rafaga_remitente_nuevo_1",
        label=PHISHING,
        description="Primero de una rafaga de tres mensajes de un remitente nuevo",
        mailbox=f"info@{ANDINA_DOMAIN}",
        sender_email="dpto.legales@estudio-vinculos.com",
        sender_display="Departamento Legales",
        subject="Notificacion judicial 1/3",
        body="""
Se le notifica que existe una causa iniciada contra la razon social.
Descargue la cedula en el enlace: http://estudio-vinculos.com/cedula/1
        """,
        expected_layers=(2, 4, 5),
        day_offset=0,
        hour=5.6,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "none", "fail"),
    ),
    Scenario(
        key="rafaga_remitente_nuevo_2",
        label=PHISHING,
        description="Segundo de la rafaga",
        mailbox=f"info@{ANDINA_DOMAIN}",
        sender_email="dpto.legales@estudio-vinculos.com",
        sender_display="Departamento Legales",
        subject="Notificacion judicial 2/3 - URGENTE",
        body="""
Reiteramos: la causa avanza a embargo si no responde en 24 horas.
http://estudio-vinculos.com/cedula/2
        """,
        expected_layers=(2, 4, 5),
        day_offset=0,
        hour=5.75,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "none", "fail"),
    ),
    Scenario(
        key="rafaga_remitente_nuevo_3",
        label=PHISHING,
        description="Tercero de la rafaga",
        mailbox=f"info@{ANDINA_DOMAIN}",
        sender_email="dpto.legales@estudio-vinculos.com",
        sender_display="Departamento Legales",
        subject="Notificacion judicial 3/3 - ultimo aviso",
        body="""
Ultimo aviso antes de la traba de embargo. Regularice ahora.
http://estudio-vinculos.com/cedula/3
        """,
        expected_layers=(2, 4, 5),
        day_offset=0,
        hour=5.9,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "none", "fail"),
    ),
    # 14. Proveedor conocido, hora imposible y desfasaje del header Date.
    Scenario(
        key="proveedor_fuera_de_horario",
        label=PHISHING,
        description="Proveedor conocido escribiendo a las 4 AM con Date adulterado",
        mailbox=f"pagos@{ANDINA_DOMAIN}",
        sender_email="cobranzas@arriba.com.ar",
        sender_display="Cobranzas Arriba Insumos",
        subject="Reenvio: orden de pago para hoy",
        body=f"""
Reenvio el pedido de pago. Por favor procesar contra esta cuenta:

CBU {CBU_ATACANTE}

Necesitamos la confirmacion antes de las 10.
        """,
        expected_layers=(1, 4, 5),
        day_offset=-1,
        hour=4.0,
        mailer="Roundcube Webmail 1.4.0",
        declared_offset_minutes=430.0,
    ),
    # ----------------------------------------------------------------- #
    # Controles negativos: correos legitimos que a un motor mal calibrado
    # le parecerian sospechosos. Son la medida del falso positivo.
    # ----------------------------------------------------------------- #
    Scenario(
        key="legitimo_proveedor_nuevo",
        label=LEGITIMATE,
        description="Primer contacto real de un proveedor: no pide nada sensible",
        mailbox=f"compras@{ANDINA_DOMAIN}",
        sender_email="ventas@embalajesdelnorte.com.ar",
        sender_display="Embalajes del Norte",
        subject="Presentacion comercial - Embalajes del Norte",
        body="""
Buenos dias,

Nos presentamos: somos Embalajes del Norte, fabricantes de cajas y film
stretch en Tucuman. Nos gustaria enviarles nuestra lista de precios y, si les
interesa, coordinar una visita del representante de la zona.

Quedamos a disposicion por cualquier consulta.

Ventas
Embalajes del Norte
        """,
        expected_layers=(),
        day_offset=-1,
        hour=10.5,
    ),
    Scenario(
        key="legitimo_gerente_urgente",
        label=LEGITIMATE,
        description="El gerente real pide algo con urgencia, sin datos bancarios",
        mailbox=f"carla.gimenez@{ANDINA_DOMAIN}",
        sender_email=f"martin.bilbao@{ANDINA_DOMAIN}",
        sender_display="Martin Bilbao",
        subject="Necesito el resumen de cuentas para hoy a las 15",
        body="""
Carla, buen dia.

Necesito con urgencia el resumen de cuentas por pagar al cierre de ayer, lo
tengo que llevar a la reunion con el banco a las 15 h. Con el PDF del sistema
alcanza, no hace falta que lo armes a mano.

Gracias!
Martin Bilbao
Socio gerente
Distribuidora Andina SA
Tel +54 9 11 4788-2210
        """,
        expected_layers=(),
        day_offset=0,
        hour=9.0,
        mailer="Apple Mail (2.3731.700.6)",
    ),
    Scenario(
        key="legitimo_deposito_temprano",
        label=LEGITIMATE,
        description="Empleado de deposito escribiendo a las 6 AM, que es su horario habitual",
        mailbox=f"compras@{ANDINA_DOMAIN}",
        sender_email=f"rodrigo.sosa@{ANDINA_DOMAIN}",
        sender_display="Rodrigo Sosa",
        subject="Faltantes para el armado de hoy",
        body="""
Buen dia, arranco con el armado y me faltan dos pallets de film. Fijense si
entra el camion de Arriba hoy asi lo descargo temprano.

Rodrigo Sosa
Deposito
Distribuidora Andina SA
        """,
        expected_layers=(),
        day_offset=-1,
        hour=7.5,
        mailer="Mozilla Thunderbird 128.2",
    ),
    Scenario(
        key="legitimo_arca_real",
        label=LEGITIMATE,
        description="Notificacion real del organismo fiscal desde su dominio oficial",
        mailbox=f"carla.gimenez@{ANDINA_DOMAIN}",
        sender_email="no-responder@arca.gob.ar",
        sender_display="ARCA - Agencia de Recaudacion",
        subject="Vencimiento de presentacion mensual",
        body="""
Le recordamos que el vencimiento para la presentacion de la declaracion jurada
mensual opera el dia 20. Puede realizar la presentacion ingresando con su clave
fiscal al portal del organismo.

ARCA - Agencia de Recaudacion y Control Aduanero
        """,
        expected_layers=(),
        day_offset=-1,
        hour=6.5,
        mailer="ARCA-Notificaciones/1.0",
    ),
    Scenario(
        key="legitimo_cambio_cbu_verificado",
        label=LEGITIMATE,
        description="Cambio de CBU real, en hilo establecido y desde el dominio correcto",
        mailbox=f"pagos@{ANDINA_DOMAIN}",
        sender_email="marisa.lopez@quimicadelsur.com.ar",
        sender_display="Marisa Lopez",
        subject="RE: Actualizacion de cuenta para pagos - Quimica del Sur",
        body=f"""
Hola Carla, como venimos conversando por telefono, te confirmo por escrito el
cambio de cuenta que ya te habia anticipado el mes pasado.

Titular: Quimica del Sur SA
CUIT: {CUIT_QUIMICA}
CBU: {CBU_QUIMICA}

Como acordamos, Ana del estudio te va a llamar para que lo verifiques por el
canal habitual antes de cargarlo en el sistema.

Saludos,
Marisa Lopez
Cuentas corporativas
Quimica del Sur SA
        """,
        expected_layers=(),
        day_offset=-2,
        hour=11.0,
    ),
)


# --------------------------------------------------------------------------- #
# Ataques contra Estudio Rivas: pocos, para que el switcher de tenant muestre
# contenido claramente distinto y el aislamiento se vea en pantalla.
# --------------------------------------------------------------------------- #

RIVAS_SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        key="bec_socia_display_name",
        label=PHISHING,
        description="Suplantacion del nombre visible de la socia del estudio",
        mailbox=f"liquidaciones@{RIVAS_DOMAIN}",
        sender_email="elena.rivas.estudio@gmail.com",
        sender_display="Elena Rivas",
        subject="Cambio de cuenta para el pago de sueldos",
        body=f"""
Necesito que el pago de sueldos de este mes de Clinica San Jorge salga a esta
cuenta, hubo un cambio de banco del cliente:

CBU: {CBU_ATACANTE}

Es para hoy. No lo comentes con Tomas que esta con otro tema.

Elena
        """,
        expected_layers=(2, 3, 5),
        day_offset=0,
        hour=10.0,
        mailer="Gmail",
    ),
    Scenario(
        key="homografo_arca_rivas",
        label=PHISHING,
        description="Suplantacion del organismo fiscal con dominio parecido",
        mailbox=f"estudio@{RIVAS_DOMAIN}",
        sender_email="intimaciones@arca-gov.com.ar",
        sender_display="ARCA - Intimaciones",
        subject="Suspension de clave fiscal de sus representados",
        body="""
Se notifica la suspension preventiva de la clave fiscal de los contribuyentes a
su cargo. Valide su condicion de representante en el siguiente enlace dentro de
las 24 horas:

http://arca-gov.com.ar/representantes/validar

ARCA
        """,
        expected_layers=(2, 3, 5),
        day_offset=-1,
        hour=9.0,
        mailer="PHPMailer 6.8.0",
        auth=AuthResults("fail", "fail", "fail"),
    ),
    Scenario(
        key="legitimo_cliente_consulta",
        label=LEGITIMATE,
        description="Consulta habitual de un cliente del estudio",
        mailbox=f"liquidaciones@{RIVAS_DOMAIN}",
        sender_email="administracion@clinicasanjorge.com.ar",
        sender_display="Clinica San Jorge",
        subject="Consulta por el recibo de una empleada",
        body="""
Buen dia, necesitamos el duplicado del recibo de sueldo de agosto de una
empleada que lo extravio. Nos lo pueden reenviar cuando puedan?

Muchas gracias.
Administracion
Clinica San Jorge
        """,
        expected_layers=(),
        day_offset=-1,
        hour=11.0,
    ),
)


SCENARIOS_BY_TENANT: dict[str, tuple[Scenario, ...]] = {
    "tenant-andina": ANDINA_SCENARIOS,
    "tenant-rivas": RIVAS_SCENARIOS,
}


def scenarios_for(tenant: TenantSpec) -> tuple[Scenario, ...]:
    return SCENARIOS_BY_TENANT.get(tenant.id, ())
