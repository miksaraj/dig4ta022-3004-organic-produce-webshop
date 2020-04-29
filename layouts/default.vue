<template>
	<div>
		<navbar />
		<b-jumbotron fluid />
		<b-container id="content">
			<nuxt />
		</b-container>
		<side-drawer />
		<footer-buttons />
	</div>
</template>

<script>
import Navbar from '~/components/Navbar.vue'
import FooterButtons from '~/components/FooterButtons.vue'
import SideDrawer from '~/components/SideDrawer.vue'
export default {
	components: {
		Navbar,
		FooterButtons,
		SideDrawer
	}
}
</script>
