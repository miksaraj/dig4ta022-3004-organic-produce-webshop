<template>
	<div>
		<b-jumbotron fluid :header="section.header" lead="subheader">
			<template v-slot:lead>
				{{ !section.lead ? section.description : section.lead }}
			</template>
			<b-button class="btn-primary">Tehtävät</b-button>
		</b-jumbotron>
		<b-container fluid>
			<component
				v-for="item in items"
				:key="item.order"
				:is="item.type"
				:id="item.contentId"
			/>
		</b-container>
	</div>
</template>

<script>
import { mapGetters } from 'vuex'
const Assignment = () => import('~/components/Assignment.vue')
const MultipleChoice = () => import('~/components/MultipleChoice.vue')
const SpecialText = () => import('~/components/SpecialText.vue')
const TheoryElement = () => import('~/components/TheoryElement.vue')
const ReturnAssignment = () => import('~/components/ReturnAssignment.vue')
export default {
	components: {
		Assignment,
		MultipleChoice,
		SpecialText,
		TheoryElement,
		ReturnAssignment
	},
	computed: {
		...mapGetters({
			sectionById: 'sections/sectionById',
			sectionStructure: 'structure/sectionStructure'
		}),
		items() {
			return this.sectionStructure(this.sectionId)
		},
		sectionId() {
			return parseInt(this.$route.params.id)
		},
		section() {
			return this.sectionById(this.sectionId)
		}
	}
}
</script>
