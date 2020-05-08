<template>
	<b-form-group :label="item.label">
		<b-form-select v-model="selected" :options="item.items" />
	</b-form-group>
</template>

<script>
export default {
	name: 'SelectElement',
	data() {
		return {
			selected: null
		}
	},
	computed: {
		item() {
			return this.$attrs.item
		}
	}
}
</script>
