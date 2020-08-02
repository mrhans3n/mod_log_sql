# Copyright 1999-2019 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6
inherit apache-module autotools

DESCRIPTION="An Apache module for logging to an SQL database"
HOMEPAGE="http://www.outoforder.cc/projects/apache/mod_log_sql/"

EGIT_REPO_URI="https://github.com/applejack69/mod_log_sql"
KEYWORDS="amd64 mips x86"
inherit git-r3

LICENSE="Artistic"
SLOT="0"
IUSE="dbi dbd ssl mysql postgres logio mariadb"
REQUIRED_USE="mariadb? ( !mysql ) mysql? ( !mariadb )"

DEPEND="
	mariadb?  ( dev-db/mariadb-connector-c:0= )
	mysql?    ( dev-db/mysql-connector-c:0= )
	postgres? ( dev-db/postgresql )
	dbi?      ( dev-db/libdbi )
	ssl?      ( dev-libs/openssl:0= )
	"
RDEPEND="${DEPEND}"

APACHE2_MOD_CONF="42_${PN}"
APACHE2_MOD_DEFINE="LOG_SQL"

APACHE2_EXECFILES=""

DOCS=( AUTHORS CHANGELOG docs/README )
HTML_DOCS=( docs/manual.html )

need_apache2_4

pkg_setup() {
	_init_apache2
	_init_apache2_late
}

src_prepare() {
	eautoreconf
	_elibtoolize -i
	default
}

src_configure() {
	local myconf="--with-apxs=${APXS}"
	myconf="${myconf} $(usex ssl		--with-ssl-inc=/usr --disable-ssl)"
	if use mysql || use mariadb; then
	    myconf="${myconf} --with-mysql=/usr"
	else
	    myconf="${myconf} --without-mysql"
	fi
	myconf="${myconf} $(usex postgres	--with-pgsql=/usr   --without-pgsql)"
	myconf="${myconf} $(usex dbi		--with-dbi=/usr     --without-dbi)"
	myconf="${myconf} $(usex dbd		--with-dbd          --without-dbd)"
	myconf="${myconf} $(usex logio		--enable-logio      --disable-logio)"

	econf ${myconf}
}

src_compile() {
	emake
}

src_install() {
	if use mysql || use mariadb; then
	    APACHE2_EXECFILES="${APACHE2_EXECFILES} .libs/${PN}_mysql.so"
	fi
	use postgres && APACHE2_EXECFILES="${APACHE2_EXECFILES} .libs/${PN}_pgsql.so"
	use dbi      && APACHE2_EXECFILES="${APACHE2_EXECFILES} .libs/${PN}_dbi.so"
	use ssl      && APACHE2_EXECFILES="${APACHE2_EXECFILES} .libs/${PN}_ssl.so"
	use logio    && APACHE2_EXECFILES="${APACHE2_EXECFILES} .libs/${PN}_logio.so"
	use dbd      && APACHE2_EXECFILES="${APACHE2_EXECFILES} .libs/${PN}_dbd"
	apache-module_src_install
	einstalldocs
}

pkg_postinst() {
	if use mysql || use mariadb; then
	    APACHE2_MOD_DEFINE="${APACHE2_MOD_DEFINE} LOG_SQL_MYSQL"
	fi
	use postgres && APACHE2_MOD_DEFINE="${APACHE2_MOD_DEFINE} LOG_SQL_PGSQL"
	use dbi      && APACHE2_MOD_DEFINE="${APACHE2_MOD_DEFINE} LOG_SQL_DBI"
	use ssl      && APACHE2_MOD_DEFINE="${APACHE2_MOD_DEFINE} LOG_SQL_SSL"
	use logio    && APACHE2_MOD_DEFINE="${APACHE2_MOD_DEFINE} LOG_SQL_LOGIO"
	use dbd      && APACHE2_MOD_DEFINE="${APACHE2_MOD_DEFINE} LOG_SQL_DBD"
	apache-module_pkg_postinst
	einfo "Refer to /usr/share/doc/${PF}/ for scripts"
	einfo "on how to create logging tables."
}
