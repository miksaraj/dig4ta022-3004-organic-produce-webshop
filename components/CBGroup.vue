<template>
	<b-form-group :label="item.label">
		<b-form-checkbox-group
			v-model="selected"
			:options="item.items"
			size="lg"
			button-variant="primary"
			buttons
			:stacked="item.stacked"
			@change="checkAnswer"
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
	methods: {
		checkAnswer() {
			/**
			 * check if selected and correctAnswer arrays
			 * are identical (for true answer)
			 */
			if (
				!Array.isArray(this.selected) ||
				!Array.isArray(this.correctAnswer) ||
				this.selected.length !== this.correctAnswer.length
			) {
				this.$emit('saveAnswer', {
					idx: this.item.order,
					answer: false
				})
				return
			}
			const selectedComp = this.selected.concat().sort()
			const answerComp = this.correctAnswer.concat().sort()
			for (let i = 0; i < selectedComp.length; i++) {
				if (selectedComp[i] !== answerComp[i]) {
					this.$emit('saveAnswer', {
						idx: this.item.order,
						answer: false
					})
					return
				}
			}
			this.$emit('saveAnswer', { idx: this.item.order, answer: true })
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
