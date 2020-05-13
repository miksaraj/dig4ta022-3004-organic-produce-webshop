<template>
	<div class="form">
		<b-form v-for="item in items" :key="item.id">
			<b-form-group :label="item.label" :label-for="item.id">
				<b-form-input
					:id="item.id"
					v-model="item.input"
					:type="item.type"
					:required="item.required"
					:readonly="readOnly"
				/>
			</b-form-group>
		</b-form>
	</div>
</template>

<style>
.form {
	padding-top: 3rem;
}
</style>

<script>
export default {
	name: 'FormGroup',
	computed: {
		items() {
			return this.$attrs.items
		},
		readOnly() {
			return this.$attrs.readOnly ? this.$attrs.readOnly : false
		}
	}
}
</script>
