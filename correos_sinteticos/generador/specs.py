"""Definicion de los tenants sinteticos, su gente y sus contrapartes.

Los dos tenants replican los arquetipos del User Research de la Seccion 3.5 del
informe: Distribuidora Andina es la PyME mediana de Martin (socio gerente) y
Carla (operadora de pagos), y el Estudio Rivas es un tenant chico que existe
sobre todo para demostrar el aislamiento logico con datos visiblemente distintos.

Cada persona tiene una hora media de envio propia y un cliente de correo
estable. Eso no es decorado: es lo que le da a la capa 1 un perfil conductual
contra el cual medir desvios, y a la capa 4 un histograma agregado del tenant.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Person:
    """Casilla interna del tenant."""

    email: str
    display_name: str
    role: str
    mailer: str
    signature: str
    hour_mu: float = 11.0
    hour_sigma: float = 2.2
    is_high_value: bool = False
    # Correos salientes por semana hacia contrapartes.
    weekly_outbound: float = 6.0


@dataclass(frozen=True, slots=True)
class Counterpart:
    """Remitente externo legitimo y recurrente."""

    email: str
    display_name: str
    org: str
    kind: str  # proveedor | cliente | banco | organismo | logistica | servicio
    mailer: str
    signature: str
    hour_mu: float = 10.5
    hour_sigma: float = 2.0
    weekly_rate: float = 1.2
    # Casillas del tenant con las que habla habitualmente.
    talks_to: tuple[str, ...] = ()

    @property
    def afternoon_share(self) -> float:
        """Proporcion de envios en el pico de la tarde.

        Los remitentes automaticos (bancos, organismos) disparan a una hora fija
        y no tienen segundo pico; las personas si. Distinguirlos es lo que evita
        que el histograma agregado del tenant quede irrealmente concentrado.
        """
        return 0.0 if self.kind in {"banco", "organismo"} else 0.38


@dataclass(frozen=True, slots=True)
class TenantSpec:
    id: str
    name: str
    domains: tuple[str, ...]
    people: tuple[Person, ...]
    counterparts: tuple[Counterpart, ...]
    business_hours: tuple[int, int] = (8, 20)
    history_days: int = 90
    plan: str = "pyme"
    cuit: str = ""
    extra_counterpart_orgs: tuple[tuple[str, str, str], ...] = field(default=())
    # Pares internos que se escriben habitualmente, con su frecuencia semanal.
    # Sin esto el trafico interno se reparte al azar entre todas las
    # combinaciones y ningun par acumula historial: el correo real del gerente a
    # su administrativa aparecia como "interno que nunca escribio a esta
    # casilla", que es una senal de fraude. La estructura de quien le habla a
    # quien no es azarosa en una empresa, y el grafo tiene que reflejarlo.
    internal_pairs: tuple[tuple[str, str, float], ...] = field(default=())

    @property
    def primary_domain(self) -> str:
        return self.domains[0]

    def person(self, email: str) -> Person | None:
        return next((p for p in self.people if p.email == email), None)


MAILERS = (
    "Microsoft Outlook 16.0",
    "Apple Mail (2.3731.700.6)",
    "Mozilla Thunderbird 128.2",
    "Zimbra 8.8.15_GA_4372",
    "Roundcube Webmail 1.6.7",
)

# --------------------------------------------------------------------------- #
# Tenant 1: Distribuidora Andina SA
# --------------------------------------------------------------------------- #

ANDINA_DOMAIN = "andina.com.ar"

_ANDINA_PEOPLE = (
    Person(
        email=f"martin.bilbao@{ANDINA_DOMAIN}",
        display_name="Martin Bilbao",
        role="Socio gerente",
        mailer="Apple Mail (2.3731.700.6)",
        signature=("Martin Bilbao\nSocio gerente\nDistribuidora Andina SA\nTel +54 9 11 4788-2210"),
        hour_mu=8.5,
        hour_sigma=1.8,
        is_high_value=True,
        weekly_outbound=9.0,
    ),
    Person(
        email=f"carla.gimenez@{ANDINA_DOMAIN}",
        display_name="Carla Gimenez",
        role="Responsable administrativa",
        mailer="Microsoft Outlook 16.0",
        signature=(
            "Carla Gimenez\nAdministracion y pagos\nDistribuidora Andina SA\nTel +54 9 11 4788-2215"
        ),
        hour_mu=10.0,
        hour_sigma=1.6,
        is_high_value=True,
        weekly_outbound=14.0,
    ),
    Person(
        email=f"pagos@{ANDINA_DOMAIN}",
        display_name="Pagos Andina",
        role="Casilla de pagos",
        mailer="Microsoft Outlook 16.0",
        signature="Sector Pagos\nDistribuidora Andina SA",
        hour_mu=11.0,
        hour_sigma=1.7,
        is_high_value=True,
        weekly_outbound=10.0,
    ),
    Person(
        email=f"compras@{ANDINA_DOMAIN}",
        display_name="Compras Andina",
        role="Casilla de compras",
        mailer="Microsoft Outlook 16.0",
        signature="Sector Compras\nDistribuidora Andina SA",
        hour_mu=10.5,
        hour_sigma=1.9,
        weekly_outbound=12.0,
    ),
    Person(
        email=f"lucia.ferrer@{ANDINA_DOMAIN}",
        display_name="Lucia Ferrer",
        role="Compras",
        mailer="Microsoft Outlook 16.0",
        signature="Lucia Ferrer\nCompras\nDistribuidora Andina SA",
        hour_mu=9.5,
        hour_sigma=1.5,
        weekly_outbound=8.0,
    ),
    Person(
        email=f"gonzalo.ibarra@{ANDINA_DOMAIN}",
        display_name="Gonzalo Ibarra",
        role="Gerente comercial",
        mailer="Apple Mail (2.3731.700.6)",
        signature="Gonzalo Ibarra\nGerente comercial\nDistribuidora Andina SA",
        hour_mu=12.0,
        hour_sigma=2.4,
        weekly_outbound=7.0,
    ),
    Person(
        email=f"rodrigo.sosa@{ANDINA_DOMAIN}",
        display_name="Rodrigo Sosa",
        role="Deposito y logistica",
        mailer="Mozilla Thunderbird 128.2",
        signature="Rodrigo Sosa\nDeposito\nDistribuidora Andina SA",
        hour_mu=7.5,
        hour_sigma=1.2,
        weekly_outbound=5.0,
    ),
    Person(
        email=f"analia.quiroga@{ANDINA_DOMAIN}",
        display_name="Analia Quiroga",
        role="Ventas",
        mailer="Microsoft Outlook 16.0",
        signature="Analia Quiroga\nVentas\nDistribuidora Andina SA",
        hour_mu=11.5,
        hour_sigma=2.0,
        weekly_outbound=9.0,
    ),
    Person(
        email=f"sebastian.ruiz@{ANDINA_DOMAIN}",
        display_name="Sebastian Ruiz",
        role="Ventas",
        mailer="Microsoft Outlook 16.0",
        signature="Sebastian Ruiz\nVentas\nDistribuidora Andina SA",
        hour_mu=13.0,
        hour_sigma=2.1,
        weekly_outbound=8.0,
    ),
    Person(
        email=f"veronica.paz@{ANDINA_DOMAIN}",
        display_name="Veronica Paz",
        role="Recursos humanos",
        mailer="Roundcube Webmail 1.6.7",
        signature="Veronica Paz\nRecursos Humanos\nDistribuidora Andina SA",
        hour_mu=10.0,
        hour_sigma=1.4,
        weekly_outbound=4.0,
    ),
    Person(
        email=f"facturacion@{ANDINA_DOMAIN}",
        display_name="Facturacion Andina",
        role="Casilla de facturacion",
        mailer="Microsoft Outlook 16.0",
        signature="Sector Facturacion\nDistribuidora Andina SA",
        hour_mu=11.0,
        hour_sigma=1.6,
        weekly_outbound=11.0,
    ),
    Person(
        email=f"info@{ANDINA_DOMAIN}",
        display_name="Contacto Andina",
        role="Casilla general",
        mailer="Roundcube Webmail 1.6.7",
        signature="Distribuidora Andina SA",
        hour_mu=12.0,
        hour_sigma=3.0,
        weekly_outbound=3.0,
    ),
)

_ANDINA_COUNTERPARTS = (
    # El proveedor central de la historia: es el que el atacante va a imitar.
    Counterpart(
        email="rodolfo.ferreyra@arriba.com.ar",
        display_name="Rodolfo Ferreyra",
        org="Arriba Insumos SRL",
        kind="proveedor",
        mailer="Microsoft Outlook 16.0",
        signature=(
            "Rodolfo Ferreyra\nAdministracion de ventas\nArriba Insumos SRL\nTel (011) 4310-8890"
        ),
        hour_mu=9.5,
        weekly_rate=3.4,
        talks_to=(
            f"compras@{ANDINA_DOMAIN}",
            f"pagos@{ANDINA_DOMAIN}",
            f"carla.gimenez@{ANDINA_DOMAIN}",
            f"lucia.ferrer@{ANDINA_DOMAIN}",
        ),
    ),
    Counterpart(
        email="cobranzas@arriba.com.ar",
        display_name="Cobranzas Arriba Insumos",
        org="Arriba Insumos SRL",
        kind="proveedor",
        mailer="Zimbra 8.8.15_GA_4372",
        signature="Sector Cobranzas\nArriba Insumos SRL",
        hour_mu=11.0,
        weekly_rate=1.6,
        talks_to=(f"pagos@{ANDINA_DOMAIN}", f"carla.gimenez@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="ventas@pampalogistica.com.ar",
        display_name="Pampa Logistica",
        org="Pampa Logistica SA",
        kind="logistica",
        mailer="Zimbra 8.8.15_GA_4372",
        signature="Coordinacion de entregas\nPampa Logistica SA",
        hour_mu=8.0,
        weekly_rate=4.2,
        talks_to=(f"rodrigo.sosa@{ANDINA_DOMAIN}", f"compras@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="marisa.lopez@quimicadelsur.com.ar",
        display_name="Marisa Lopez",
        org="Quimica del Sur SA",
        kind="proveedor",
        mailer="Microsoft Outlook 16.0",
        signature="Marisa Lopez\nCuentas corporativas\nQuimica del Sur SA",
        hour_mu=10.0,
        weekly_rate=2.1,
        talks_to=(
            f"compras@{ANDINA_DOMAIN}",
            f"lucia.ferrer@{ANDINA_DOMAIN}",
            # Tambien le escribe a pagos: el control negativo del cambio de CBU
            # legitimo necesita que la relacion exista para no confundirse con un
            # primer contacto.
            f"pagos@{ANDINA_DOMAIN}",
        ),
    ),
    Counterpart(
        email="facundo.rey@envaseslitoral.com.ar",
        display_name="Facundo Rey",
        org="Envases Litoral SRL",
        kind="proveedor",
        mailer="Mozilla Thunderbird 128.2",
        signature="Facundo Rey\nEnvases Litoral SRL",
        hour_mu=9.0,
        weekly_rate=1.8,
        talks_to=(f"compras@{ANDINA_DOMAIN}",),
    ),
    Counterpart(
        email="compras@supermercadosmirasol.com.ar",
        display_name="Compras Mirasol",
        org="Supermercados Mirasol",
        kind="cliente",
        mailer="Microsoft Outlook 16.0",
        signature="Departamento de Compras\nSupermercados Mirasol",
        hour_mu=11.5,
        weekly_rate=3.8,
        talks_to=(
            f"analia.quiroga@{ANDINA_DOMAIN}",
            f"sebastian.ruiz@{ANDINA_DOMAIN}",
            f"facturacion@{ANDINA_DOMAIN}",
        ),
    ),
    Counterpart(
        email="administracion@almacenesbelgrano.com.ar",
        display_name="Administracion Belgrano",
        org="Almacenes Belgrano",
        kind="cliente",
        mailer="Roundcube Webmail 1.6.7",
        signature="Administracion\nAlmacenes Belgrano",
        hour_mu=12.5,
        weekly_rate=2.4,
        talks_to=(f"facturacion@{ANDINA_DOMAIN}", f"analia.quiroga@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="notificaciones@bancodelplata.com.ar",
        display_name="Banco del Plata",
        org="Banco del Plata",
        kind="banco",
        mailer="BancoPlata-Mailer/2.1",
        signature="Banco del Plata\nEste es un mensaje automatico.",
        hour_mu=7.0,
        hour_sigma=0.8,
        weekly_rate=3.0,
        talks_to=(f"pagos@{ANDINA_DOMAIN}", f"carla.gimenez@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="no-responder@arca.gob.ar",
        display_name="ARCA - Agencia de Recaudacion",
        org="ARCA",
        kind="organismo",
        mailer="ARCA-Notificaciones/1.0",
        signature="ARCA - Agencia de Recaudacion y Control Aduanero",
        hour_mu=6.5,
        hour_sigma=0.6,
        weekly_rate=1.1,
        talks_to=(f"carla.gimenez@{ANDINA_DOMAIN}", f"facturacion@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="estudio@rivas-contadores.com.ar",
        display_name="Estudio Rivas",
        org="Estudio Contable Rivas",
        kind="servicio",
        mailer="Microsoft Outlook 16.0",
        signature="Estudio Contable Rivas\nContadores publicos",
        hour_mu=10.5,
        weekly_rate=2.0,
        talks_to=(f"carla.gimenez@{ANDINA_DOMAIN}", f"martin.bilbao@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="diego.ocampo@redsegura.com.ar",
        display_name="Diego Ocampo",
        org="Red Segura MSP",
        kind="servicio",
        mailer="Mozilla Thunderbird 128.2",
        signature="Diego Ocampo\nSoporte tecnico\nRed Segura MSP",
        hour_mu=14.0,
        hour_sigma=2.8,
        weekly_rate=1.5,
        talks_to=(f"martin.bilbao@{ANDINA_DOMAIN}", f"info@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="ventas@ferreteriaindustrialnorte.com.ar",
        display_name="Ferreteria Industrial Norte",
        org="Ferreteria Industrial Norte",
        kind="proveedor",
        mailer="Roundcube Webmail 1.6.7",
        signature="Ventas\nFerreteria Industrial Norte",
        hour_mu=8.5,
        weekly_rate=1.4,
        talks_to=(f"compras@{ANDINA_DOMAIN}", f"rodrigo.sosa@{ANDINA_DOMAIN}"),
    ),
    Counterpart(
        email="rrhh@consultoraaltamira.com.ar",
        display_name="Consultora Altamira",
        org="Consultora Altamira",
        kind="servicio",
        mailer="Microsoft Outlook 16.0",
        signature="Consultora Altamira\nSeleccion de personal",
        hour_mu=13.5,
        weekly_rate=0.9,
        talks_to=(f"veronica.paz@{ANDINA_DOMAIN}",),
    ),
    Counterpart(
        email="soporte@sistemasgestionar.com.ar",
        display_name="Gestionar Sistemas",
        org="Gestionar Sistemas",
        kind="servicio",
        mailer="Zimbra 8.8.15_GA_4372",
        signature="Mesa de ayuda\nGestionar Sistemas",
        hour_mu=15.0,
        weekly_rate=1.2,
        talks_to=(f"facturacion@{ANDINA_DOMAIN}", f"info@{ANDINA_DOMAIN}"),
    ),
)

# Contrapartes secundarias, generadas para que el grafo del tenant tenga la
# densidad de una PyME real (decenas de interlocutores, no una docena).
_ANDINA_EXTRA_ORGS = (
    ("Distribuidora Cuyo", "cuyodistribuciones.com.ar", "cliente"),
    ("Insumos Rosario", "insumosrosario.com.ar", "proveedor"),
    ("Transporte Vera", "transportevera.com.ar", "logistica"),
    ("Papelera Delta", "papeleradelta.com.ar", "proveedor"),
    ("Mayorista Sur", "mayoristasur.com.ar", "cliente"),
    ("Etiquetas Precisas", "etiquetasprecisas.com.ar", "proveedor"),
    ("Refrigeracion Austral", "refrigeracionaustral.com.ar", "servicio"),
    ("Autoelevadores Prisma", "prismaelevadores.com.ar", "servicio"),
    ("Almacen Don Pedro", "almacendonpedro.com.ar", "cliente"),
    ("Comercial Tucuman", "comercialtucuman.com.ar", "cliente"),
    ("Seguros Andes", "segurosandes.com.ar", "servicio"),
    ("Limpieza Total", "limpiezatotalsrl.com.ar", "servicio"),
    ("Bebidas Serranas", "bebidasserranas.com.ar", "proveedor"),
    ("Kiosco Central", "kioscocentral.com.ar", "cliente"),
    ("Grafica Once", "graficaonce.com.ar", "proveedor"),
    ("Herrajes Belgrano", "herrajesbelgrano.com.ar", "proveedor"),
    ("Deposito Fiscal Norte", "depositofiscalnorte.com.ar", "logistica"),
    ("Consorcio Edificio Lavalle", "consorciolavalle.com.ar", "servicio"),
    ("Telecomunicaciones Fibra", "fibraconecta.com.ar", "servicio"),
    ("Gas Envasado Litoral", "gaslitoral.com.ar", "proveedor"),
    ("Cooperativa La Union", "coopunion.com.ar", "cliente"),
    ("Uniformes Trabajo Ya", "trabajoya.com.ar", "proveedor"),
    ("Control de Plagas Higia", "higiacontrol.com.ar", "servicio"),
    ("Mantenimiento Volta", "voltamantenimiento.com.ar", "servicio"),
)

_ANDINA_INTERNAL_PAIRS = (
    (f"martin.bilbao@{ANDINA_DOMAIN}", f"carla.gimenez@{ANDINA_DOMAIN}", 4.0),
    (f"carla.gimenez@{ANDINA_DOMAIN}", f"martin.bilbao@{ANDINA_DOMAIN}", 3.5),
    (f"martin.bilbao@{ANDINA_DOMAIN}", f"gonzalo.ibarra@{ANDINA_DOMAIN}", 2.5),
    (f"carla.gimenez@{ANDINA_DOMAIN}", f"pagos@{ANDINA_DOMAIN}", 3.0),
    (f"pagos@{ANDINA_DOMAIN}", f"carla.gimenez@{ANDINA_DOMAIN}", 2.8),
    (f"compras@{ANDINA_DOMAIN}", f"pagos@{ANDINA_DOMAIN}", 2.5),
    (f"lucia.ferrer@{ANDINA_DOMAIN}", f"compras@{ANDINA_DOMAIN}", 3.0),
    (f"rodrigo.sosa@{ANDINA_DOMAIN}", f"compras@{ANDINA_DOMAIN}", 2.5),
    (f"analia.quiroga@{ANDINA_DOMAIN}", f"facturacion@{ANDINA_DOMAIN}", 3.0),
    (f"sebastian.ruiz@{ANDINA_DOMAIN}", f"facturacion@{ANDINA_DOMAIN}", 2.0),
    (f"gonzalo.ibarra@{ANDINA_DOMAIN}", f"analia.quiroga@{ANDINA_DOMAIN}", 2.0),
    (f"veronica.paz@{ANDINA_DOMAIN}", f"martin.bilbao@{ANDINA_DOMAIN}", 1.5),
    (f"facturacion@{ANDINA_DOMAIN}", f"carla.gimenez@{ANDINA_DOMAIN}", 2.5),
    (f"martin.bilbao@{ANDINA_DOMAIN}", f"pagos@{ANDINA_DOMAIN}", 1.8),
    (f"rodrigo.sosa@{ANDINA_DOMAIN}", f"lucia.ferrer@{ANDINA_DOMAIN}", 1.6),
    (f"veronica.paz@{ANDINA_DOMAIN}", f"info@{ANDINA_DOMAIN}", 1.2),
)

ANDINA = TenantSpec(
    id="tenant-andina",
    name="Distribuidora Andina SA",
    domains=(ANDINA_DOMAIN,),
    people=_ANDINA_PEOPLE,
    counterparts=_ANDINA_COUNTERPARTS,
    # Una distribuidora con deposito propio abre temprano: el turno de Rodrigo
    # arranca antes que la administracion.
    business_hours=(7, 19),
    history_days=90,
    plan="pyme",
    cuit="30-71234567-1",
    extra_counterpart_orgs=_ANDINA_EXTRA_ORGS,
    internal_pairs=_ANDINA_INTERNAL_PAIRS,
)


# --------------------------------------------------------------------------- #
# Tenant 2: Estudio Contable Rivas
# --------------------------------------------------------------------------- #

RIVAS_DOMAIN = "rivas-contadores.com.ar"

_RIVAS_PEOPLE = (
    Person(
        email=f"estudio@{RIVAS_DOMAIN}",
        display_name="Estudio Rivas",
        role="Casilla general",
        mailer="Microsoft Outlook 16.0",
        signature="Estudio Contable Rivas",
        hour_mu=10.0,
        weekly_outbound=10.0,
    ),
    Person(
        email=f"elena.rivas@{RIVAS_DOMAIN}",
        display_name="Elena Rivas",
        role="Socia",
        mailer="Apple Mail (2.3731.700.6)",
        signature="Elena Rivas\nContadora publica\nEstudio Contable Rivas",
        hour_mu=9.0,
        is_high_value=True,
        weekly_outbound=8.0,
    ),
    Person(
        email=f"liquidaciones@{RIVAS_DOMAIN}",
        display_name="Liquidaciones Rivas",
        role="Liquidacion de sueldos",
        mailer="Microsoft Outlook 16.0",
        signature="Sector Liquidaciones\nEstudio Contable Rivas",
        hour_mu=11.5,
        is_high_value=True,
        weekly_outbound=9.0,
    ),
    Person(
        email=f"tomas.aguirre@{RIVAS_DOMAIN}",
        display_name="Tomas Aguirre",
        role="Analista contable",
        mailer="Mozilla Thunderbird 128.2",
        signature="Tomas Aguirre\nEstudio Contable Rivas",
        hour_mu=13.0,
        weekly_outbound=6.0,
    ),
    Person(
        email=f"recepcion@{RIVAS_DOMAIN}",
        display_name="Recepcion Rivas",
        role="Recepcion",
        mailer="Roundcube Webmail 1.6.7",
        signature="Recepcion\nEstudio Contable Rivas",
        hour_mu=10.5,
        weekly_outbound=4.0,
    ),
)

_RIVAS_COUNTERPARTS = (
    Counterpart(
        email="carla.gimenez@andina.com.ar",
        display_name="Carla Gimenez",
        org="Distribuidora Andina SA",
        kind="cliente",
        mailer="Microsoft Outlook 16.0",
        signature="Carla Gimenez\nAdministracion y pagos\nDistribuidora Andina SA",
        hour_mu=10.0,
        weekly_rate=2.2,
        talks_to=(
            f"estudio@{RIVAS_DOMAIN}",
            f"liquidaciones@{RIVAS_DOMAIN}",
            f"elena.rivas@{RIVAS_DOMAIN}",
        ),
    ),
    Counterpart(
        email="no-responder@arca.gob.ar",
        display_name="ARCA - Agencia de Recaudacion",
        org="ARCA",
        kind="organismo",
        mailer="ARCA-Notificaciones/1.0",
        signature="ARCA - Agencia de Recaudacion y Control Aduanero",
        hour_mu=6.5,
        hour_sigma=0.6,
        weekly_rate=2.6,
        talks_to=(f"estudio@{RIVAS_DOMAIN}", f"elena.rivas@{RIVAS_DOMAIN}"),
    ),
    Counterpart(
        email="administracion@clinicasanjorge.com.ar",
        display_name="Clinica San Jorge",
        org="Clinica San Jorge",
        kind="cliente",
        mailer="Zimbra 8.8.15_GA_4372",
        signature="Administracion\nClinica San Jorge",
        hour_mu=11.0,
        weekly_rate=1.9,
        talks_to=(f"liquidaciones@{RIVAS_DOMAIN}", f"tomas.aguirre@{RIVAS_DOMAIN}"),
    ),
    Counterpart(
        email="pagos@constructoraelpilar.com.ar",
        display_name="Constructora El Pilar",
        org="Constructora El Pilar",
        kind="cliente",
        mailer="Microsoft Outlook 16.0",
        signature="Sector Pagos\nConstructora El Pilar",
        hour_mu=9.5,
        weekly_rate=1.7,
        talks_to=(f"estudio@{RIVAS_DOMAIN}",),
    ),
)

_RIVAS_EXTRA_ORGS = (
    ("Panaderia La Espiga", "laespiga.com.ar", "cliente"),
    ("Taller Mecanico Rueda", "tallerrueda.com.ar", "cliente"),
    ("Optica Vision", "opticavision.com.ar", "cliente"),
    ("Farmacia del Centro", "farmaciadelcentro.com.ar", "cliente"),
    ("Colegio San Martin", "colegiosanmartin.edu.ar", "cliente"),
    ("Inmobiliaria Portal", "inmobiliariaportal.com.ar", "cliente"),
)

_RIVAS_INTERNAL_PAIRS = (
    (f"elena.rivas@{RIVAS_DOMAIN}", f"liquidaciones@{RIVAS_DOMAIN}", 3.0),
    (f"liquidaciones@{RIVAS_DOMAIN}", f"elena.rivas@{RIVAS_DOMAIN}", 2.5),
    (f"tomas.aguirre@{RIVAS_DOMAIN}", f"elena.rivas@{RIVAS_DOMAIN}", 2.0),
    (f"recepcion@{RIVAS_DOMAIN}", f"estudio@{RIVAS_DOMAIN}", 2.0),
    (f"estudio@{RIVAS_DOMAIN}", f"elena.rivas@{RIVAS_DOMAIN}", 2.0),
    (f"elena.rivas@{RIVAS_DOMAIN}", f"tomas.aguirre@{RIVAS_DOMAIN}", 2.2),
)

RIVAS = TenantSpec(
    id="tenant-rivas",
    name="Estudio Contable Rivas",
    domains=(RIVAS_DOMAIN,),
    people=_RIVAS_PEOPLE,
    counterparts=_RIVAS_COUNTERPARTS,
    internal_pairs=_RIVAS_INTERNAL_PAIRS,
    business_hours=(9, 18),
    history_days=90,
    plan="pyme",
    # Digito verificador calculado con el algoritmo de AFIP, no inventado.
    cuit="30-64789012-8",
    extra_counterpart_orgs=_RIVAS_EXTRA_ORGS,
)


ALL_TENANTS: tuple[TenantSpec, ...] = (ANDINA, RIVAS)
