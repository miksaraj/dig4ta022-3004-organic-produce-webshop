<template>
	<b-card>
		<h2>
			<nuxt-link :to="'/courses/' + item.id">{{ item.header }}</nuxt-link>
		</h2>
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
