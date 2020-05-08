<template>
	<b-form-group :label="item.label">
		<b-form-checkbox-group
			v-model="selected"
			:options="item.items"
			:stacked="item.stacked"
		/>
	</b-form-group>
</template>

<script>
export default {
	name: 'CBGroup',
	data() {
		return {
			selected: []
		}
	},
	computed: {
		item() {
			return this.$attrs.item
		}
	}
}
</script>
