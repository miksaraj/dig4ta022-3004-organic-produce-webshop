<template>
	<b-card>
		<nuxt-link to="/courses/1">{{ item.header }}</nuxt-link>
		<p>{{ item.description }}</p>
	</b-card>
</template>

<script>
export default {
	name: 'card',
	computed: {
		item() {
			return this.$attrs.item
		}
	}
}
</script>
