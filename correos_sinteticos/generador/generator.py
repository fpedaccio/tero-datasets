"""Generador determinista del buzon sintetico.

Produce, para cada tenant, tres cosas distintas:

1. **Historial** (``is_history=True``): 90 dias de trafico legitimo con horarios
   propios de cada persona, hilos, firmas estables y clientes de correo
   consistentes. No se muestra en la bandeja ni entra en las metricas: existe
   para que las capas 1, 2 y 4 tengan un perfil contra el cual medir. Sin
   historial esas tres capas no tienen nada que decir, y una demo sin historial
   solo puede lucir la capa semantica.

2. **Bandeja reciente** (``is_history=False``, legitimos): correos normales de
   las ultimas 48 horas. Son los que demuestran que el motor deja pasar lo que
   tiene que dejar pasar.

3. **Escenarios** (``is_history=False``, con ground truth): los ataques y los
   controles negativos de ``attacks.py``.

Los perfiles se construyen **solo** con el historial, nunca con la bandeja
reciente. Es una decision metodologica, no una comodidad: si un correo
contribuyera al perfil contra el cual se lo evalua, el motor estaria haciendo
trampa consigo mismo y las metricas serian optimistas.

La generacion es determinista: mismo ``AP_RANDOM_SEED``, mismo buzon. La semilla
se combina con el id del tenant para que agregar un tenant no altere los datos
de los demas.
"""

from __future__ import annotations

import argparse
import random
from collections.abc import Iterator
from datetime import date, datetime, time, timedelta

from antiphishing.calendar_ar import (
    business_day_at_or_before,
    business_days_back,
    previous_business_day,
    resolve_business_stamp,
)
from antiphishing.config import get_settings
from antiphishing.db import create_all, migrate_to_head, session_scope
from antiphishing.ingest.base import Address, AuthResults, NormalizedEmail
from antiphishing.models_db import (
    Mailbox,
    Message,
    RelationshipRow,
    SenderProfileRow,
    Tenant,
    User,
)
from antiphishing.persistence import make_vault, store_email
from antiphishing.preprocess.pii import PIIAnonymizer
from antiphishing.profiling import ProfileBuilder
from antiphishing.seed.attacks import scenarios_for
from antiphishing.seed.specs import ALL_TENANTS, Counterpart, Person, TenantSpec
from antiphishing.seguridad import hashear_contrasena
from antiphishing.tenancy import TenantScope

# Contrasena de las cuentas de demo. Publica a proposito, igual que la clave
# maestra de desarrollo: es lo que permite entrar al panel tras `make seed`.
CONTRASENA_DEMO = "tero-demo-2026"

_hash_demo_cache: str | None = None


def _hash_demo() -> str:
    """Hash de la contrasena demo, calculado una sola vez por corrida."""
    global _hash_demo_cache
    if _hash_demo_cache is None:
        _hash_demo_cache = hashear_contrasena(CONTRASENA_DEMO)
    return _hash_demo_cache


# Hilo historico al que responde el escenario "cambio_cbu_en_hilo": el ataque
# se inserta en una conversacion que realmente existio.
ANCHOR_THREAD_ID = "thread-factura-18472"
ANCHOR_MESSAGE_ID = "<hist-arriba-18472@arriba.com.ar>"

BUSINESS_DAYS_PER_WEEK = 5.0

# Dias habiles que el historial deja libres al final para la bandeja visible.
# La bandeja se ubica en los dos ultimos dias habiles y puede correrse uno mas
# hacia atras si la hora pedida de hoy todavia no ocurrio, asi que reservar
# cuatro garantiza que nunca se solapen. El corte tiene que contarse en dias
# habiles y no calendario: con un lunes feriado, "tres dias antes" y "el ultimo
# dia habil" son el mismo viernes, y el historial terminaba pisando la bandeja.
HISTORY_GAP_BUSINESS_DAYS = 4


# --------------------------------------------------------------------------- #
# Plantillas de contenido legitimo
# --------------------------------------------------------------------------- #

# Plantillas de contenido legitimo.
#
# Son largas y con detalles concretos a proposito. La primera version tenia
# cuerpos de dos oraciones (~150 caracteres) y eso produjo un problema real: los
# correos legitimos de SpaPhish, con los que se entreno la capa semantica, tienen
# una mediana de 1.093 caracteres, asi que plantillas de 150 quedaban **fuera de
# la distribucion** del modelo. BETO les asignaba probabilidades erraticas -0,99
# a una "Solicitud de cotizacion" legitima- y el buzon sintetico dejaba de ser un
# banco de pruebas valido para la capa 5.
#
# Un correo comercial real tiene saludo, contexto, numeros concretos, un pedido y
# un cierre. Estas plantillas lo replican.

_PROVEEDOR = (
    (
        "Remito {num} - entrega programada para el {fecha}",
        "Buen dia,\n\n"
        "Les confirmamos que el remito {num} sale de nuestro deposito el {fecha} por "
        "la manana. El transporte es el habitual y estiman llegar entre las 9 y las 11.\n\n"
        "Van {bultos} bultos en total. Como la ultima vez quedo una diferencia en el "
        "conteo, esta vez el chofer lleva la planilla firmada para que la controlen en "
        "el momento de la descarga.\n\n"
        "Cualquier cosa me escriben o me llaman al interno de siempre.\n\n"
        "Saludos,",
    ),
    (
        "Factura {serie}-{num} - vencimiento a 30 dias",
        "Estimados,\n\n"
        "Adjuntamos la factura {serie}-{num} correspondiente a los pedidos despachados "
        "durante el mes, por un total de {monto}.\n\n"
        "El vencimiento opera a 30 dias de la fecha de emision. Como siempre, si "
        "necesitan que la desdoblemos por centro de costos nos avisan y la reemitimos "
        "sin problema.\n\n"
        "Quedamos a disposicion por cualquier consulta sobre el detalle.\n\n"
        "Saludos cordiales,",
    ),
    (
        "Lista de precios con vigencia desde el {fecha}",
        "Buenos dias,\n\n"
        "Les enviamos la lista de precios actualizada, con vigencia desde el {fecha}.\n\n"
        "Los ajustes promedian el 4 % sobre la lista anterior y estan concentrados en "
        "los articulos importados. Las lineas nacionales quedan sin cambios. Los items "
        "en promocion estan marcados en la ultima columna y mantienen el precio hasta "
        "fin de mes.\n\n"
        "Si tienen pedidos en curso con la lista anterior, los respetamos a valor viejo.\n\n"
        "Saludos,",
    ),
    (
        "Demora en el pedido {num}",
        "Hola, como estan.\n\n"
        "Les aviso que tenemos una demora de dos dias habiles en el pedido {num}. El "
        "faltante viene del proveedor del insumo importado, que reprogramo su entrega.\n\n"
        "Lo que si tenemos disponible es el resto del pedido: si les sirve, lo podemos "
        "despachar parcial ahora y completar la semana que viene, sin costo adicional "
        "de flete.\n\n"
        "Me confirman como prefieren y lo dejo armado.\n\n"
        "Disculpen la molestia,",
    ),
    (
        "RE: consulta por disponibilidad de stock",
        "Hola,\n\n"
        "Te confirmo que tenemos disponibilidad de lo que consultaste: hay {bultos} "
        "unidades en el deposito central y entra reposicion la semana proxima.\n\n"
        "Si te sirve te reservo el stock hasta el viernes sin compromiso. Pasado ese "
        "dia lo libero porque tengo otro cliente preguntando por la misma linea.\n\n"
        "Avisame y lo dejo apartado a tu nombre.\n\n"
        "Saludos,",
    ),
)

_CLIENTE = (
    (
        "Pedido {num} segun cotizacion",
        "Buen dia,\n\n"
        "Queremos confirmar el pedido {num} tomando la ultima cotizacion que nos "
        "enviaron, con las cantidades que habiamos conversado por telefono.\n\n"
        "Necesitariamos saber el plazo de entrega estimado, porque tenemos que "
        "coordinar la recepcion en el deposito y esta semana esta complicado por "
        "inventario.\n\n"
        "La orden de compra formal la emitimos en cuanto nos confirmen el plazo.\n\n"
        "Gracias,",
    ),
    (
        "Consulta por factura {serie}-{num}",
        "Hola, buen dia.\n\n"
        "Necesitamos el duplicado de la factura {serie}-{num} porque no la encontramos "
        "en nuestro sistema y contaduria la esta pidiendo para cerrar el periodo.\n\n"
        "Aprovecho para consultar si esa factura incluye el flete o si viene por "
        "separado, porque el monto no nos coincide con lo presupuestado.\n\n"
        "Si nos la pueden reenviar por este medio les agradecemos.\n\n"
        "Gracias,",
    ),
    (
        "Comprobante de transferencia por {monto}",
        "Buenas tardes,\n\n"
        "Adjuntamos el comprobante de la transferencia por {monto}, que cubre el saldo "
        "pendiente de las facturas del mes pasado.\n\n"
        "La operacion salio hoy a la manana desde nuestra cuenta habitual, asi que "
        "deberia estar acreditada en el transcurso del dia.\n\n"
        "Quedamos a la espera de la imputacion en cuenta corriente y del recibo "
        "correspondiente.\n\n"
        "Saludos,",
    ),
    (
        "Reclamo por mercaderia faltante en la entrega del {fecha}",
        "Buen dia,\n\n"
        "En la entrega del {fecha} nos faltaron dos bultos respecto de lo que figura "
        "en el remito {num}. El chofer nos hizo firmar la planilla completa, asi que "
        "quedo la diferencia sin registrar.\n\n"
        "Ya revisamos el deposito por si habian quedado mal ubicados y no aparecen. "
        "Les pedimos que lo verifiquen con la gente de expedicion.\n\n"
        "Necesitamos resolverlo esta semana porque esa mercaderia esta comprometida "
        "con un cliente.\n\n"
        "Gracias,",
    ),
    (
        "Solicitud de cotizacion por volumen",
        "Hola,\n\n"
        "Estamos armando el presupuesto del proximo trimestre y necesitariamos una "
        "cotizacion por volumen para las lineas que venimos comprando.\n\n"
        "La idea es cerrar un acuerdo de precio por tres meses a cambio de un volumen "
        "mensual garantizado, algo parecido a lo que hicimos el ano pasado.\n\n"
        "Si les interesa podemos coordinar una reunion para ver numeros. Nos avisan "
        "que dia les queda comodo.\n\n"
        "Saludos,",
    ),
)

_BANCO = (
    (
        "Resumen de cuenta disponible",
        "Le informamos que el resumen de su cuenta empresa correspondiente al ultimo "
        "periodo ya se encuentra disponible.\n\n"
        "Puede consultarlo y descargarlo ingresando a la banca electronica con su "
        "usuario habitual, en la seccion de cuentas.\n\n"
        "Este es un mensaje automatico. Por su seguridad, el banco nunca le solicita "
        "datos de acceso por correo electronico.\n\n",
    ),
    (
        "Acreditacion registrada en su cuenta empresa",
        "Le informamos que se registro una acreditacion en su cuenta empresa.\n\n"
        "Puede consultar el detalle de la operacion, el ordenante y el importe "
        "ingresando a la banca electronica con su usuario habitual.\n\n"
        "Este es un mensaje automatico. Por su seguridad, el banco nunca le solicita "
        "datos de acceso por correo electronico.\n\n",
    ),
    (
        "Vencimiento proximo de plazo fijo",
        "Le recordamos que su plazo fijo vence en los proximos dias habiles.\n\n"
        "Si desea renovarlo, puede gestionarlo desde la banca electronica hasta el dia "
        "del vencimiento inclusive. De no mediar instruccion, el capital y los "
        "intereses se acreditan en su cuenta corriente.\n\n"
        "Este es un mensaje automatico. Por su seguridad, el banco nunca le solicita "
        "datos de acceso por correo electronico.\n\n",
    ),
)

_ORGANISMO = (
    (
        "Recordatorio de vencimiento de presentacion mensual",
        "Le recordamos que se aproxima el vencimiento para la presentacion de la "
        "declaracion jurada mensual correspondiente al periodo en curso.\n\n"
        "La presentacion se realiza ingresando al portal del organismo con clave "
        "fiscal, en el servicio correspondiente al regimen en el que se encuentra "
        "inscripto.\n\n"
        "El presente mensaje tiene caracter informativo y no constituye notificacion "
        "en los terminos de la normativa vigente.\n\n",
    ),
    (
        "Constancia disponible para descarga",
        "Le informamos que la constancia solicitada se encuentra disponible para su "
        "descarga.\n\n"
        "Puede obtenerla ingresando al portal del organismo con clave fiscal, en el "
        "servicio de constancias e inscripciones. La constancia tiene una validez de "
        "treinta dias corridos desde su emision.\n\n"
        "El presente mensaje tiene caracter informativo y no constituye notificacion "
        "en los terminos de la normativa vigente.\n\n",
    ),
)

_LOGISTICA = (
    (
        "Hoja de ruta del {fecha}",
        "Buen dia,\n\n"
        "Les enviamos la hoja de ruta correspondiente al {fecha}. El camion sale del "
        "deposito a las 7 h y tiene {bultos} paradas programadas.\n\n"
        "El recorrido arranca por la zona sur y termina en el centro, asi que las "
        "entregas de esa zona quedan para la tarde. Si alguna es urgente avisennos "
        "antes de las 6 para reordenar el reparto.\n\n"
        "El chofer lleva el telefono de siempre por cualquier novedad en el camino.\n\n"
        "Saludos,",
    ),
    (
        "Confirmacion de retiro para manana",
        "Hola,\n\n"
        "Confirmamos el retiro de la mercaderia para manana temprano, entre las 7 y "
        "las 8 de la manana.\n\n"
        "Necesitamos que este paletizada y con la documentacion lista, porque el "
        "camion tiene otra carga despues y no puede esperar. Si no llega a estar, "
        "avisennos hoy para reprogramar sin costo.\n\n"
        "Saludos,",
    ),
    (
        "Novedad en la entrega {num}",
        "Buen dia,\n\n"
        "La entrega {num} quedo reprogramada: el chofer llego al domicilio y no habia "
        "nadie para recibir, esperó cuarenta minutos y tuvo que seguir el recorrido.\n\n"
        "La mercaderia vuelve al deposito y queda disponible para reintentar. "
        "Necesitamos que confirmen un dia y una franja horaria con el cliente antes de "
        "volver a salir, para no repetir el viaje en falso.\n\n"
        "Saludos,",
    ),
)

_SERVICIO = (
    (
        "Mantenimiento programado para la semana proxima",
        "Buen dia,\n\n"
        "Les recordamos que la semana que viene corresponde el mantenimiento "
        "preventivo incluido en el contrato de servicio.\n\n"
        "La visita lleva alrededor de tres horas y conviene coordinarla en un horario "
        "de poco movimiento, porque hay que interrumpir el equipo. Nos dicen que dia y "
        "hora les resulta mas comodo y lo agendamos.\n\n"
        "Si surgio alguna falla desde la ultima visita, avisennos para que el tecnico "
        "vaya con los repuestos correspondientes.\n\n"
        "Saludos,",
    ),
    (
        "Ticket {num} resuelto",
        "Hola,\n\n"
        "Les informamos que el ticket {num} quedo resuelto. La causa era una "
        "configuracion desactualizada que ya corregimos, y probamos el circuito "
        "completo antes de cerrarlo.\n\n"
        "Si el problema vuelve a presentarse, respondan sobre este mismo mensaje y "
        "reabrimos el caso conservando el historial, asi no hay que explicar todo de "
        "nuevo.\n\n"
        "Gracias por la paciencia,",
    ),
    (
        "Renovacion de servicio - detalle de condiciones",
        "Estimados,\n\n"
        "El contrato de servicio se renueva el mes que viene y les adjuntamos el "
        "detalle de las condiciones para el nuevo periodo.\n\n"
        "Las condiciones se mantienen en lo esencial. El unico cambio es el ajuste "
        "anual del abono, que sigue el indice previsto en el contrato original.\n\n"
        "Si quieren revisar el alcance o incorporar equipos, podemos coordinar una "
        "llamada antes de la fecha de renovacion.\n\n"
        "Saludos,",
    ),
)

_OUTBOUND = (
    (
        "RE: {asunto}",
        "Hola, como estas.\n\n"
        "Recibido. Lo estoy revisando con el sector y te confirmo a la brevedad, "
        "calculo que manana a primera hora.\n\n"
        "Si necesitas algo antes de eso, escribime y lo vemos.\n\n"
        "Saludos,",
    ),
    (
        "Confirmacion de pedido {num}",
        "Buen dia,\n\n"
        "Confirmamos el pedido {num} con las cantidades que acordamos por telefono. "
        "La orden de compra sale hoy por el sistema.\n\n"
        "Quedamos a la espera del remito para coordinar la recepcion en el deposito. "
        "Si van a despachar parcial, avisennos antes asi preparamos el espacio.\n\n"
        "Saludos,",
    ),
    (
        "Orden de pago emitida por {monto}",
        "Buen dia,\n\n"
        "Emitimos la orden de pago por {monto}, que cubre el saldo pendiente de las "
        "facturas vencidas hasta la fecha.\n\n"
        "La transferencia sale en el proximo lote de pagos, que procesamos los martes "
        "y los jueves. En cuanto se acredite les enviamos el comprobante.\n\n"
        "Cualquier diferencia en el detalle nos avisan antes de que salga.\n\n"
        "Saludos,",
    ),
    (
        "Consulta por diferencia entre remito y factura",
        "Hola,\n\n"
        "Necesitamos aclarar una diferencia que encontramos entre el remito {num} y la "
        "factura correspondiente: los bultos declarados no coinciden.\n\n"
        "Puede ser que hayan facturado una entrega anterior en el mismo comprobante, "
        "pero preferimos confirmarlo antes de imputarla en cuenta corriente.\n\n"
        "Nos podes ayudar a revisarlo?\n\n"
        "Gracias,",
    ),
)

_INTERNO = (
    (
        "Reunion de equipo del {fecha}",
        "Buen dia a todos,\n\n"
        "Recordatorio de la reunion de equipo del {fecha}. Es la reunion mensual "
        "habitual, en la sala de arriba.\n\n"
        "Lleven el avance de sus temas anotado, aunque sea en dos lineas, asi no se nos "
        "va la hora en poner a todos al dia. Si alguien no puede venir, que mande su "
        "resumen por mail antes.\n\n"
        "Gracias,",
    ),
    (
        "Planilla de la semana actualizada",
        "Hola,\n\n"
        "Adjunto la planilla actualizada con los movimientos de la semana. Revisen las "
        "columnas de su sector antes del viernes, porque despues la cierro para armar "
        "el informe.\n\n"
        "Hay algunas celdas en amarillo que quedaron sin dato: si les corresponde, "
        "completenlas o avisenme que no aplica.\n\n"
        "Gracias,",
    ),
    (
        "Faltante de stock en dos articulos",
        "Buen dia,\n\n"
        "Aviso que quedo faltante de stock en dos articulos de la linea principal. "
        "Compras ya lo esta gestionando con el proveedor habitual.\n\n"
        "Mientras tanto, si entra un pedido de esos codigos conviene avisarle al "
        "cliente antes de confirmar la fecha, para no prometer algo que no vamos a "
        "poder cumplir.\n\n"
        "Cualquier duda me preguntan.\n\n"
        "Saludos,",
    ),
    (
        "Cierre del mes: comprobantes pendientes",
        "Hola a todos,\n\n"
        "Recordatorio de que el cierre del mes es el viernes. Necesitamos que manden "
        "los comprobantes pendientes antes del jueves al mediodia.\n\n"
        "El mes pasado varios llegaron despues del cierre y hubo que reabrir el "
        "periodo, asi que esta vez les pido que lo tengan en cuenta. Si algo no va a "
        "llegar en fecha, avisenme para verlo.\n\n"
        "Gracias,",
    ),
)

_TEMPLATES_BY_KIND = {
    "proveedor": _PROVEEDOR,
    "cliente": _CLIENTE,
    "banco": _BANCO,
    "organismo": _ORGANISMO,
    "logistica": _LOGISTICA,
    "servicio": _SERVICIO,
}


class SyntheticMailboxGenerator:
    """Genera el trafico de un tenant de forma reproducible."""

    def __init__(self, spec: TenantSpec, reference: datetime, seed: int) -> None:
        self.spec = spec
        self.reference = reference
        # La semilla se combina con el id del tenant para que los tenants sean
        # independientes entre si.
        self.rng = random.Random(f"{seed}:{spec.id}")
        self._counter = 0
        self.counterparts: tuple[Counterpart, ...] = tuple(spec.counterparts) + tuple(
            self._build_extra_counterparts()
        )

    # -- utilidades ------------------------------------------------------- #

    def _next_id(self, prefix: str, domain: str) -> str:
        self._counter += 1
        return f"<{prefix}-{self.spec.id}-{self._counter:05d}@{domain}>"

    def _build_extra_counterparts(self) -> Iterator[Counterpart]:
        """Convierte la lista de organizaciones secundarias en contrapartes.

        Le dan al grafo del tenant la densidad de una PyME real: decenas de
        interlocutores con vinculos de fuerza variada, que es lo que hace que la
        senal de "vinculo debil" de la capa 2 signifique algo.
        """
        mailbox_pool = [p.email for p in self.spec.people]
        for index, (org, domain, kind) in enumerate(self.spec.extra_counterpart_orgs):
            local = ("ventas", "administracion", "contacto", "compras")[index % 4]
            talks_to = tuple(self.rng.sample(mailbox_pool, k=min(2, len(mailbox_pool))))
            yield Counterpart(
                email=f"{local}@{domain}",
                display_name=org,
                org=org,
                kind=kind,
                mailer=self.rng.choice(
                    ("Microsoft Outlook 16.0", "Roundcube Webmail 1.6.7", "Zimbra 8.8.15_GA_4372")
                ),
                signature=f"{org}",
                # Se acota el modo de la manana para que, corrido al pico de la
                # tarde, no se salga de la jornada laboral.
                hour_mu=self.rng.uniform(8.5, 12.5),
                hour_sigma=self.rng.uniform(1.2, 2.2),
                weekly_rate=self.rng.uniform(0.25, 1.1),
                talks_to=talks_to,
            )

    def _sample_time(
        self, day: date, hour_mu: float, hour_sigma: float, afternoon_share: float = 0.38
    ) -> datetime:
        """Hora de envio muestreada alrededor del habito del remitente.

        La distribucion es bimodal: un pico a la manana y otro despues del
        mediodia. Con un solo modo gaussiano el trafico se apilaba antes de las
        13 h y el histograma agregado del tenant describia una jornada que
        terminaba a las 15 h. Eso importa porque la capa 4 mide "fuera del
        patron horario" contra ese histograma: un horario laboral irrealmente
        corto haria que cualquier correo de la tarde pareciera anomalo.
        """
        mu = hour_mu + (5.0 if self.rng.random() < afternoon_share else 0.0)
        hour = self.rng.gauss(mu, hour_sigma)
        hour = max(6.0, min(21.99, hour))
        whole = int(hour)
        minute = int((hour - whole) * 60)
        return datetime.combine(day, time(whole, minute, self.rng.randrange(60)))

    def _draw_count(self, daily_rate: float) -> int:
        """Cantidad de correos del dia para una tasa diaria dada."""
        whole = int(daily_rate)
        remainder = daily_rate - whole
        return whole + (1 if self.rng.random() < remainder else 0)

    @staticmethod
    def _fill(template: str, rng: random.Random, extra: dict | None = None) -> str:
        values = {
            "num": f"{rng.randrange(10_000, 99_999)}",
            "serie": f"A-{rng.randrange(1, 9):04d}",
            "fecha": f"{rng.randrange(1, 28)}/{rng.randrange(1, 13)}",
            "asunto": "su consulta",
            "bultos": f"{rng.randrange(3, 40)}",
            # Los importes se escriben con formato argentino para que el detector
            # de PII los reconozca como montos, igual que en un correo real.
            "monto": f"$ {rng.randrange(80, 2400)}.{rng.randrange(100, 999)},00",
        }
        if extra:
            values.update(extra)
        try:
            return template.format(**values)
        except (KeyError, IndexError):
            return template

    def _email(
        self,
        *,
        sender: Address,
        mailbox: str,
        subject: str,
        body: str,
        stamp: datetime,
        mailer: str,
        signature: str,
        thread_id: str | None = None,
        message_id: str | None = None,
        in_reply_to: str | None = None,
        auth: AuthResults | None = None,
    ) -> NormalizedEmail:
        domain = sender.domain or "localhost"
        # Linea en blanco entre el cuerpo y la firma, como en un correo real. Con
        # un solo salto de linea el extractor de firmas no podia separarlas y
        # arrastraba el ultimo parrafo del cuerpo dentro de la "firma": como ese
        # parrafo cambia con cada plantilla, la capa 1 veia que la firma del
        # remitente cambiaba en cada mensaje y emitia un falso positivo.
        full_body = f"{body}\n\n{signature}" if signature else body
        return NormalizedEmail(
            message_id=message_id or self._next_id("hist", domain),
            tenant_id=self.spec.id,
            mailbox=mailbox,
            sender=sender,
            subject=subject,
            body_text=full_body,
            sent_at=stamp,
            received_at=stamp + timedelta(seconds=self.rng.randrange(20, 240)),
            source="synthetic",
            recipients=(Address(email=mailbox),),
            thread_id=thread_id,
            in_reply_to=in_reply_to,
            headers={
                "X-Mailer": mailer,
                "Return-Path": f"<{sender.email}>",
                "Authentication-Results": "spf=pass; dkim=pass; dmarc=pass",
            },
            auth=auth or AuthResults("pass", "pass", "pass"),
        )

    # -- generacion ------------------------------------------------------- #

    def history(self) -> list[NormalizedEmail]:
        """Trafico legitimo de los ultimos ``history_days`` dias."""
        emails: list[NormalizedEmail] = []
        people = list(self.spec.people)
        mailbox_emails = [p.email for p in people]

        # El historial corta antes de los dias habiles reservados a la bandeja.
        # Si se solapara, un correo podria contribuir al perfil contra el cual se
        # lo evalua y las metricas del informe saldrian optimistas.
        cutoff = business_days_back(self.reference.date(), HISTORY_GAP_BUSINESS_DAYS)

        for days_ago in range(self.spec.history_days, 0, -1):
            day = (self.reference - timedelta(days=days_ago)).date()
            if day >= cutoff:
                continue
            is_weekend = day.weekday() >= 5

            for counterpart in self.counterparts:
                daily = counterpart.weekly_rate / BUSINESS_DAYS_PER_WEEK
                if is_weekend:
                    daily *= 0.08
                for _ in range(self._draw_count(daily)):
                    emails.append(self._counterpart_email(counterpart, day, mailbox_emails))

            for person in people:
                daily = person.weekly_outbound / BUSINESS_DAYS_PER_WEEK
                if is_weekend:
                    daily *= 0.05
                for _ in range(self._draw_count(daily)):
                    emails.append(self._outbound_email(person, day))

            if not is_weekend:
                # Pares internos habituales: la estructura de quien le escribe a
                # quien en una empresa no es azarosa, y el grafo tiene que
                # reflejarlo o el correo real del gerente a su administrativa
                # parece un primer contacto.
                for sender_email, recipient_email, weekly in self.spec.internal_pairs:
                    for _ in range(self._draw_count(weekly / BUSINESS_DAYS_PER_WEEK)):
                        pair = self._internal_pair_email(sender_email, recipient_email, day)
                        if pair is not None:
                            emails.append(pair)

                for _ in range(self._draw_count(1.2)):
                    internal = self._internal_email(people, day)
                    if internal is not None:
                        emails.append(internal)

        emails.append(self._anchor_thread_email())
        emails.sort(key=lambda e: e.sent_at)
        return emails

    def _counterpart_email(
        self, counterpart: Counterpart, day: date, mailbox_pool: list[str]
    ) -> NormalizedEmail:
        targets = counterpart.talks_to or tuple(mailbox_pool)
        mailbox = self.rng.choice(targets)
        templates = _TEMPLATES_BY_KIND.get(counterpart.kind, _SERVICIO)
        subject_tpl, body_tpl = self.rng.choice(templates)
        return self._email(
            sender=Address(email=counterpart.email, display_name=counterpart.display_name),
            mailbox=mailbox,
            subject=self._fill(subject_tpl, self.rng),
            body=self._fill(body_tpl, self.rng),
            stamp=self._sample_time(
                day, counterpart.hour_mu, counterpart.hour_sigma, counterpart.afternoon_share
            ),
            mailer=counterpart.mailer,
            signature=counterpart.signature,
        )

    def _outbound_email(self, person: Person, day: date) -> NormalizedEmail:
        counterpart = self.rng.choice(self.counterparts)
        subject_tpl, body_tpl = self.rng.choice(_OUTBOUND)
        return self._email(
            sender=Address(email=person.email, display_name=person.display_name),
            mailbox=counterpart.email,
            subject=self._fill(subject_tpl, self.rng),
            body=self._fill(body_tpl, self.rng),
            stamp=self._sample_time(day, person.hour_mu, person.hour_sigma),
            mailer=person.mailer,
            signature=person.signature,
        )

    def _internal_pair_email(
        self, sender_email: str, recipient_email: str, day: date
    ) -> NormalizedEmail | None:
        sender = self.spec.person(sender_email)
        if sender is None or self.spec.person(recipient_email) is None:
            return None
        subject_tpl, body_tpl = self.rng.choice(_INTERNO)
        return self._email(
            sender=Address(email=sender.email, display_name=sender.display_name),
            mailbox=recipient_email,
            subject=self._fill(subject_tpl, self.rng),
            body=self._fill(body_tpl, self.rng),
            stamp=self._sample_time(day, sender.hour_mu, sender.hour_sigma),
            mailer=sender.mailer,
            signature=sender.signature,
        )

    def _internal_email(self, people: list[Person], day: date) -> NormalizedEmail | None:
        if len(people) < 2:
            return None
        sender, recipient = self.rng.sample(people, 2)
        subject_tpl, body_tpl = self.rng.choice(_INTERNO)
        return self._email(
            sender=Address(email=sender.email, display_name=sender.display_name),
            mailbox=recipient.email,
            subject=self._fill(subject_tpl, self.rng),
            body=self._fill(body_tpl, self.rng),
            stamp=self._sample_time(day, sender.hour_mu, sender.hour_sigma),
            mailer=sender.mailer,
            signature=sender.signature,
        )

    def _anchor_thread_email(self) -> NormalizedEmail:
        """El correo real de facturacion en el que despues se inserta el ataque.

        Solo aplica a Andina; para los demas tenants es un correo mas.
        """
        if self.spec.id != "tenant-andina":
            counterpart = self.counterparts[0]
            day = business_day_at_or_before((self.reference - timedelta(days=6)).date())
            return self._counterpart_email(counterpart, day, [p.email for p in self.spec.people])

        # Dia habil, en horario y bien dentro del historial: el ataque en hilo
        # responde a un correo verosimil que ya contribuyo al perfil.
        stamp = resolve_business_stamp(self.reference, HISTORY_GAP_BUSINESS_DAYS + 2, 10.5)
        return self._email(
            sender=Address(
                email="cobranzas@arriba.com.ar",
                display_name="Cobranzas Arriba Insumos",
            ),
            mailbox="carla.gimenez@andina.com.ar",
            subject="Factura A-0004-00018472 - vencimiento",
            body=(
                "Carla, buen dia.\n\nTe envio la factura A-0004-00018472 por "
                "$ 1.184.300,00 con vencimiento a 30 dias. Cualquier duda me "
                "escribis.\n\nAbrazo,"
            ),
            stamp=stamp,
            mailer="Zimbra 8.8.15_GA_4372",
            signature="Sector Cobranzas\nArriba Insumos SRL",
            thread_id=ANCHOR_THREAD_ID,
            message_id=ANCHOR_MESSAGE_ID,
        )

    def recent_inbox(self, count: int) -> list[NormalizedEmail]:
        """Correos legitimos recientes, visibles en la bandeja.

        Son los que demuestran que el motor no marca todo: sin ellos la bandeja
        seria una lista de ataques y el falso positivo no se podria observar.

        Caen en los dos ultimos dias habiles y, dentro de ellos, **en la hora
        habitual de su propio remitente**, muestreada de la misma distribucion que
        uso el historial.

        Esto ultimo hizo falta corregirlo. Una version anterior repartia los
        correos a lo largo de la jornada del tenant ignorando el habito de cada
        remitente, y eso produjo un falso positivo sistematico: el organismo
        fiscal notifica siempre a las 6:30, asi que al ubicar su correo a las 9:30
        la capa 1 detectaba -con razon- que ese remitente nunca escribe a esa
        hora. El correo era legitimo y la capa funcionaba bien; el defecto estaba
        en los datos. Muestrear del habito de cada remitente mantiene coherentes a
        la vez la capa 1 (que compara al remitente contra si mismo) y la capa 4
        (que exige dia habil).
        """
        emails: list[NormalizedEmail] = []
        mailbox_pool = [p.email for p in self.spec.people]

        for index in range(count):
            # Se alternan los dos ultimos dias habiles.
            day_offset = index % 2
            if self.rng.random() < 0.7:
                counterpart = self.rng.choice(self.counterparts)
                targets = counterpart.talks_to or tuple(mailbox_pool)
                templates = _TEMPLATES_BY_KIND.get(counterpart.kind, _SERVICIO)
                subject_tpl, body_tpl = self.rng.choice(templates)
                sender = Address(email=counterpart.email, display_name=counterpart.display_name)
                mailbox = self.rng.choice(targets)
                mailer, signature = counterpart.mailer, counterpart.signature
                hour_mu, hour_sigma = counterpart.hour_mu, counterpart.hour_sigma
                afternoon = counterpart.afternoon_share
            else:
                person, recipient = self.rng.sample(list(self.spec.people), 2)
                subject_tpl, body_tpl = self.rng.choice(_INTERNO)
                sender = Address(email=person.email, display_name=person.display_name)
                mailbox = recipient.email
                mailer, signature = person.mailer, person.signature
                hour_mu, hour_sigma = person.hour_mu, person.hour_sigma
                afternoon = 0.38

            dia = business_days_back(self.reference.date(), day_offset)
            stamp = self._sample_time(dia, hour_mu, hour_sigma, afternoon)
            # Si la hora muestreada de hoy todavia no ocurrio, se corre al dia
            # habil anterior para que el correo no quede en el futuro.
            while stamp > self.reference:
                dia = previous_business_day(dia)
                stamp = self._sample_time(dia, hour_mu, hour_sigma, afternoon)

            emails.append(
                self._email(
                    sender=sender,
                    mailbox=mailbox,
                    subject=self._fill(subject_tpl, self.rng),
                    body=self._fill(body_tpl, self.rng),
                    stamp=stamp,
                    mailer=mailer,
                    signature=signature,
                    message_id=self._next_id("inbox", sender.domain or "localhost"),
                )
            )
        return emails

    def scenario_emails(self) -> list[NormalizedEmail]:
        return [s.to_email(self.spec, self.reference) for s in scenarios_for(self.spec)]


# --------------------------------------------------------------------------- #
# Sembrado
# --------------------------------------------------------------------------- #


def _upsert_tenant(session, spec: TenantSpec) -> None:
    tenant = session.get(Tenant, spec.id)
    if tenant is None:
        session.add(
            Tenant(
                id=spec.id,
                name=spec.name,
                domains=list(spec.domains),
                plan=spec.plan,
                business_hours_start=spec.business_hours[0],
                business_hours_end=spec.business_hours[1],
            )
        )
    else:
        tenant.name = spec.name
        tenant.domains = list(spec.domains)
        tenant.business_hours_start = spec.business_hours[0]
        tenant.business_hours_end = spec.business_hours[1]
    session.flush()


def _upsert_mailboxes(scope: TenantScope, spec: TenantSpec) -> None:
    existing = {row.email for row in scope.all(scope.select(Mailbox))}
    for person in spec.people:
        if person.email in existing:
            continue
        scope.add(
            Mailbox(
                email=person.email,
                display_name=person.display_name,
                role=person.role,
                is_high_value=person.is_high_value,
            )
        )
    scope.flush()


def _upsert_users(scope: TenantScope, spec: TenantSpec) -> int:
    """Cuentas del panel con contrasena conocida, para la demo con login.

    La primera persona del spec queda como propietaria, la segunda como
    administradora, la tercera como analista y el resto como lectores. Cada
    cuenta se vincula a su propia casilla vigilada: es lo que habilita la vista
    de empleado (ver ``User.mailbox_id``).
    """
    existentes = {row.email for row in scope.all(scope.select(User))}
    casillas = {row.email: row.id for row in scope.all(scope.select(Mailbox))}
    roles = ("propietario", "administrador", "analista")

    creadas = 0
    for indice, person in enumerate(spec.people):
        if person.email in existentes:
            continue
        scope.add(
            User(
                email=person.email,
                full_name=person.display_name,
                role=roles[indice] if indice < len(roles) else "lector",
                status="activo",
                invited_by="seed",
                password_hash=_hash_demo(),
                mailbox_id=casillas.get(person.email),
            )
        )
        creadas += 1
    scope.flush()
    return creadas


def seed_tenant(
    session,
    spec: TenantSpec,
    reference: datetime,
    seed: int,
    recent_count: int,
) -> dict[str, int]:
    """Siembra un tenant completo. Devuelve un resumen contable."""
    _upsert_tenant(session, spec)
    scope = TenantScope(session, spec.id)
    _upsert_mailboxes(scope, spec)
    cuentas = _upsert_users(scope, spec)

    anonymizer = PIIAnonymizer(
        known_names=[p.display_name for p in spec.people]
        + [c.display_name for c in spec.counterparts],
        known_emails=[p.email for p in spec.people],
    )
    vault = make_vault(spec.id)

    generator = SyntheticMailboxGenerator(spec, reference, seed)

    history = generator.history()
    for email in history:
        store_email(scope, email, anonymizer, vault, is_history=True)
    scope.flush()

    # Los perfiles y el grafo se construyen unicamente con el historial.
    builder = ProfileBuilder(scope)
    builder.observe_all(history)
    profiles, edges = builder.flush(spec.domains)

    recent = generator.recent_inbox(recent_count)
    for email in recent:
        store_email(scope, email, anonymizer, vault, is_history=False)

    scenarios = generator.scenario_emails()
    for email in scenarios:
        store_email(scope, email, anonymizer, vault, is_history=False)
    scope.flush()

    return {
        "historial": len(history),
        "bandeja": len(recent),
        "escenarios": len(scenarios),
        "perfiles": profiles,
        "aristas": edges,
        "contrapartes": len(generator.counterparts),
        "cuentas": cuentas,
    }


def seed_database(
    reference: datetime | None = None,
    recent_count: int = 22,
    reset: bool = False,
) -> dict[str, dict[str, int]]:
    """Siembra todos los tenants. Idempotente por ``message_id``."""
    settings = get_settings()
    create_all()
    migrate_to_head()
    # Se ancla a la hora en punto para que la bandeja tenga marcas prolijas.
    anchor = (reference or datetime.now()).replace(minute=0, second=0, microsecond=0)

    summary: dict[str, dict[str, int]] = {}
    with session_scope() as session:
        if reset:
            # Se borran tambien los perfiles y las aristas, no solo los correos.
            #
            # ``store_email`` es idempotente por message_id, pero ``_merge_profile``
            # **suma**: si el reset dejaba los perfiles en pie, cada siembra
            # acumulaba sobre la anterior. Un remitente con 89 correos de historial
            # terminaba con perfiles de varias corridas mezcladas, incluidas las
            # previas a un cambio en la logica de perfilado. Eso produjo un falso
            # positivo concreto: la firma acumulada de nueve corridas tenia 96
            # variantes, y la comparacion contra la unica del mensaje actual daba
            # "la firma cambio" sobre correo legitimo.
            #
            # El upsert acumulativo es deliberado y correcto para la
            # sincronizacion incremental de Gmail; lo que estaba mal era resembrar
            # sin limpiar.
            for spec in ALL_TENANTS:
                scope = TenantScope(session, spec.id)
                for modelo in (Message, SenderProfileRow, RelationshipRow):
                    for row in scope.all(scope.select(modelo)):
                        session.delete(row)
            session.flush()

        for spec in ALL_TENANTS:
            summary[spec.id] = seed_tenant(
                session, spec, anchor, settings.random_seed, recent_count
            )
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera el buzon sintetico de la demo")
    parser.add_argument(
        "--reference",
        help="Fecha de referencia ISO (por defecto, ahora). Fijarla hace la corrida reproducible.",
    )
    parser.add_argument(
        "--recent", type=int, default=22, help="Correos legitimos visibles por tenant"
    )
    parser.add_argument(
        "--reset", action="store_true", help="Borra los correos previos antes de sembrar"
    )
    args = parser.parse_args()

    reference = datetime.fromisoformat(args.reference) if args.reference else None
    summary = seed_database(reference=reference, recent_count=args.recent, reset=args.reset)

    print("\nBuzon sintetico generado\n" + "=" * 46)
    for tenant_id, counts in summary.items():
        print(f"\n{tenant_id}")
        for key, value in counts.items():
            print(f"  {key:<14} {value:>6}")
    total = sum(c["historial"] + c["bandeja"] + c["escenarios"] for c in summary.values())
    print(f"\n  total de correos: {total}")

    print("\nCuentas del panel (contrasena unica de demo: " + CONTRASENA_DEMO + ")")
    for spec in ALL_TENANTS:
        roles = ("propietario", "administrador", "analista")
        print(f"\n{spec.id}")
        for indice, person in enumerate(spec.people):
            rol = roles[indice] if indice < len(roles) else "lector"
            print(f"  {rol:<14} {person.email}")

    print("\nSiguiente paso: make eval (o make dev para levantar la API)\n")


if __name__ == "__main__":
    main()
