<template>
	<b-navbar sticky toggleable>
		<b-navbar-brand>
			<nuxt-link to="/">
				<img
					src="../static/oppia.io_logo_oranssi.png"
					alt="Oppia.io"
					width="152"
					height="48"
				/>
			</nuxt-link>
		</b-navbar-brand>
		<b-navbar-toggle target="navbar-toggle-collapse">
			<template v-slot:default="{ expanded }">
				<b-icon v-if="expanded" icon="x-circle" />
				<b-icon v-else icon="grid" />
			</template>
		</b-navbar-toggle>
		<b-collapse id="navbar-toggle-collapse" is-nav>
			<b-navbar-nav class="ml-auto">
				<b-nav-item>
					<nuxt-link to="/" class="nav-link">Etusivu</nuxt-link>
				</b-nav-item>
				<b-nav-item>
					<nuxt-link to="/profile" class="nav-link">
						Profiili
					</nuxt-link>
				</b-nav-item>
				<b-nav-item>Asetukset</b-nav-item>
				<b-nav-item>Edistyminen</b-nav-item>
				<b-nav-item @click="logout">Kirjaudu ulos</b-nav-item>
			</b-navbar-nav>
		</b-collapse>
	</b-navbar>
</template>

<style scoped>
.navbar-brand a {
	color: var(--color-main);
	font-weight: bolder;
	-webkit-text-fill-color: var(--color-main);
	-webkit-text-stroke-width: 2px;
	-webkit-text-stroke-color: #ffffff;
}

.navbar {
	background-color: var(--color-main);
}

.navbar-toggler {
	color: #ffffff;
	border-color: #ffffff;
}

.navbar-nav {
	float: right;
}

.nav-link {
	color: #ffffff !important;
}

.nav-link:hover,
.nav-link:active {
	color: antiquewhite !important;
}

.nav-link .nav-link {
	padding: unset;
}
</style>

<script>
export default {
	name: 'Navbar',
	methods: {
		logout() {
			localStorage.removeItem('user')
			this.$router.push('/login')
		}
	}
}
</script>
