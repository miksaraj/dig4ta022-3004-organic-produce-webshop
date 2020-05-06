<template>
	<b-card id="assignment">
		<h2>Tehtävä:</h2>
		<p></p>
		<b-form-textarea
			id="textarea-rows"
			placeholder="Tall textarea"
			rows="8"
		/>
	</b-card>
</template>

<script>
export default {
	name: 'assignment',
	computed: {
		item() {
			return this.$attrs.item
		}
	}
}
</script>
