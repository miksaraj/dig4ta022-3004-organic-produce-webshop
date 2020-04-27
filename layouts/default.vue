<template>
	<div>
		<navbar />
		<b-jumbotron fluid />
		<b-container id="content">
			<nuxt />
		</b-container>
	</div>
</template>

<script>
import Navbar from '~/components/Navbar.vue'
export default {
	components: {
		Navbar
	}
}
</script>
