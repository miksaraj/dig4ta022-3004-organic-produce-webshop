<template>
	<b-form-group :label="item.label">
		<b-form-radio-group
			v-model="selected"
			:options="item.items"
			:stacked="item.stacked"
			@change="checkAnswer"
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
