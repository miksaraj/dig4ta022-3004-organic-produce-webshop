<template>
	<b-card>
		<h1>{{ item.header }}</h1>
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
