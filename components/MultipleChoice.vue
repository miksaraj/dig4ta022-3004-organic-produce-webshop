<template>
	<b-form>
		<h3>{{ item.header }}</h3>
		<component
			v-for="part in item.parts"
			:key="part.order"
			:is="part.type"
			:item="part"
			@saveAnswer="saveAnswer"
		/>
		<b-button class="btn-primary" @click="handleSubmit">Lähetä</b-button>
	</b-form>
</template>

<script>
import { mapGetters } from 'vuex'
const CBGroup = () => import('~/components/CBGroup.vue')
const RadioGroup = () => import('~/components/RadioGroup.vue')
const SelectElement = () => import('~/components/SelectElement.vue')
export default {
	name: 'MultipleChoice',
	components: {
		CBGroup,
		RadioGroup,
		SelectElement
	},
	data() {
		return {
			assignmentProgress: []
		}
	},
	computed: {
		...mapGetters('content', ['contentById']),
		item() {
			return this.contentById(this.id)
		},
		id() {
			return this.$attrs.id
		}
	},
	methods: {
		handleSubmit() {
			if (this.assignmentProgress.length < this.item.parts.length) {
				alert('Muista vastata kaikkiin kohtiin!')
			} else {
				let correct = 0
				for (let i = 0; i < this.assignmentProgress.length; i++) {
					const question = this.assignmentProgress[i]
					if (question.answer === true) {
						correct++
					}
				}
				alert(correct + '/' + this.item.parts.length + ' oikein!')
				this.$store.dispatch('progress/markAsDone', this.id)
			}
		},
		saveAnswer(data) {
			const index = this.assignmentProgress.findIndex(
				x => x.idx === data.idx
			)
			if (index === -1) {
				this.$set(
					this.assignmentProgress,
					this.assignmentProgress.length,
					data
				)
			} else {
				this.$set(this.assignmentProgress, index, data)
			}
		}
	}
}
</script>
