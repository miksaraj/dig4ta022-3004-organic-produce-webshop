<template>
	<b-form-group :label="item.label">
		<b-form-radio-group
			v-model="selected"
			:options="item.items"
			:stacked="item.stacked"
		/>
	</b-form-group>
</template>

<script>
export default {
	name: 'RadioGroup',
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
