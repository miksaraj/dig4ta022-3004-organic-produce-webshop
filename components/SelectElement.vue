<template>
	<b-form-group :label="item.label">
		<b-form-select
			v-model="selected"
			:options="item.items"
			@change="checkAnswer"
		/>
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
	methods: {
		checkAnswer() {
			let answer = false
			if (this.selected === this.correctAnswer) {
				answer = true
			}
			this.$emit('saveAnswer', { idx: this.item.order, answer })
		}
	},
	computed: {
		item() {
			return this.$attrs.item
		},
		correctAnswer() {
			return this.item.correctAnswer
		}
	}
}
</script>
