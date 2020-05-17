<template>
	<div>
		<navbar />
		<b-jumbotron fluid>
			<nav-breadcrumbs v-if="$route.name.includes('chapters-id')" />
		</b-jumbotron>
		<b-container id="content">
			<nuxt />
		</b-container>
		<side-drawer />
		<footer-buttons />
		<footer-component />
	</div>
</template>

<script>
import Navbar from '~/components/Navbar.vue'
import FooterButtons from '~/components/FooterButtons.vue'
import SideDrawer from '~/components/SideDrawer.vue'
import FooterComponent from '~/components/FooterComponent.vue'
import NavBreadcrumbs from '~/components/NavBreadcrumbs.vue'
export default {
	components: {
		Navbar,
		FooterButtons,
		SideDrawer,
		FooterComponent,
		NavBreadcrumbs
	}
}
</script>
